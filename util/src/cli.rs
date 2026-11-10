// Copyright 2026 The MWC Developers
// Licensed under the Apache License, Version 2.0.

//! Shared loading and querying of the node and wallet's embedded CLI schemas.

use mwc_crates::clap::builder::{OsStringValueParser, PossibleValuesParser, TypedValueParser};
use mwc_crates::clap::{Arg, ArgAction, ArgMatches, Command};
use mwc_crates::yaml_rust2::Yaml;
use std::ffi::{OsStr, OsString};

/// Build a Clap command from a compiled-in YAML schema.
///
/// Clap 4 no longer provides a YAML loader. Keep the existing schemas as the
/// single source of command definitions, and reject unsupported schema fields
/// rather than silently dropping their validation. Invalid embedded schemas
/// are programming errors and panic, as they did with Clap's former loader.
pub fn command_from_yaml(yaml: &Yaml) -> Command {
	command(yaml["name"].as_str().expect("CLI command name"), yaml)
}

fn command(name: &str, yaml: &Yaml) -> Command {
	let mut cmd = Command::new(name.to_owned());
	for (key, value) in yaml.as_hash().expect("CLI command mapping") {
		cmd =
			match key.as_str().expect("CLI command field") {
				"name" => cmd,
				"version" => cmd.version(string(value)),
				"author" => cmd.author(string(value)),
				"about" => cmd.about(string(value)),
				"args" => cmd.args(
					value
						.as_vec()
						.expect("CLI argument list")
						.iter()
						.map(argument),
				),
				"subcommands" => {
					cmd.subcommands(value.as_vec().expect("CLI subcommand list").iter().map(
						|entry| {
							let (name, body) = entry
								.as_hash()
								.expect("CLI subcommand mapping")
								.iter()
								.next()
								.expect("CLI subcommand");
							command(name.as_str().expect("CLI subcommand name"), body)
						},
					))
				}
				other => panic!("Unsupported CLI command field: {other}"),
			};
	}
	// Several wallet commands already use -h for a height. Clap 2 reserved only
	// --help in that case; retain those short options instead of conflicting.
	let short_help_available = !cmd.get_arguments().any(|arg| arg.get_short() == Some('h'));
	let mut help = Arg::new("help")
		.long("help")
		.action(ArgAction::Help)
		.help("Print help");
	if short_help_available {
		help = help.short('h');
	}
	cmd.disable_help_flag(true).arg(help)
}

fn string(value: &Yaml) -> String {
	value.as_str().expect("CLI string value").to_owned()
}

fn argument(entry: &Yaml) -> Arg {
	let (name, yaml) = entry
		.as_hash()
		.expect("CLI argument mapping")
		.iter()
		.next()
		.expect("CLI argument");
	let mut arg = Arg::new(string(name));
	let positional = yaml["short"].is_badvalue() && yaml["long"].is_badvalue();
	let takes_value = positional || yaml["takes_value"].as_bool().unwrap_or(false);
	arg = if takes_value {
		// Preserve non-UTF-8 paths and let command-specific validation report
		// malformed text values. Values remain strings at the wallet boundary.
		arg.action(ArgAction::Set)
			.value_parser(OsStringValueParser::new())
	} else {
		arg.action(ArgAction::SetTrue)
	};
	for (key, value) in yaml.as_hash().expect("CLI argument definition") {
		arg = match key.as_str().expect("CLI argument field") {
			"help" => arg.help(string(value)),
			"short" => arg.short(
				string(value)
					.trim_start_matches('-')
					.chars()
					.next()
					.expect("CLI short option"),
			),
			"long" => arg.long(string(value)),
			"takes_value" => arg,
			"required" => arg.required(value.as_bool().expect("CLI required boolean")),
			"index" => arg.index(value.as_i64().expect("CLI positional index") as usize),
			"default_value" => arg.default_value(string(value)),
			"possible_values" => arg.value_parser(
				PossibleValuesParser::new(
					value
						.as_vec()
						.expect("CLI possible values")
						.iter()
						.map(string),
				)
				.map(OsString::from),
			),
			other => panic!("Unsupported CLI argument field: {other}"),
		};
	}
	arg
}

/// Queries used by the shared command handlers.
///
/// Optional arguments may be absent from a command's schema. Clap 4's typed
/// getters panic on unknown IDs; these queries retain the handlers' optional
/// lookup behavior and distinguish absent flags from their `false` defaults.
pub trait ArgMatchesExt {
	/// First UTF-8 value, including a schema default.
	fn value_of(&self, name: &str) -> Option<&str>;
	/// First platform-native value, including a schema default.
	fn value_of_os(&self, name: &str) -> Option<&OsStr>;
	/// All platform-native values, including schema defaults.
	fn values_of_os(&self, name: &str) -> Option<impl Iterator<Item = &OsStr>>;
	/// Whether a value is present or a boolean flag is set.
	fn is_present(&self, name: &str) -> bool;
}

impl ArgMatchesExt for ArgMatches {
	fn value_of(&self, name: &str) -> Option<&str> {
		self.value_of_os(name).and_then(OsStr::to_str)
	}

	fn value_of_os(&self, name: &str) -> Option<&OsStr> {
		self.try_get_one::<OsString>(name)
			.ok()
			.flatten()
			.map(OsString::as_os_str)
	}

	fn values_of_os(&self, name: &str) -> Option<impl Iterator<Item = &OsStr>> {
		self.try_get_many::<OsString>(name)
			.ok()
			.flatten()
			.map(|values| values.map(OsString::as_os_str))
	}

	fn is_present(&self, name: &str) -> bool {
		match self.try_get_one::<bool>(name) {
			Ok(value) => value.copied().unwrap_or(false),
			Err(_) => self.try_contains_id(name).unwrap_or(false),
		}
	}
}
