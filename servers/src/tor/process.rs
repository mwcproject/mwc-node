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

// BSD 3-Clause License
//
// Copyright (c) 2016, Dhole
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this
//   list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
//   this list of conditions and the following disclaimer in the documentation
//   and/or other materials provided with the distribution.
//
// * Neither the name of the copyright holder nor the names of its
//   contributors may be used to endorse or promote products derived from
//   this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Tor process control
//! Derived from from from https://github.com/Dhole/rust-tor-controller.git

extern crate chrono;

use regex::Regex;
use std::fs::{self, File};
use std::io;
use std::io::Write;
use std::io::{BufRead, BufReader};
use std::path::{Path, MAIN_SEPARATOR};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::mpsc::channel;
use std::thread;
use sysinfo::{Process, ProcessExt, Signal};

#[cfg(windows)]
const TOR_EXE_NAME: &str = "tor.exe";
#[cfg(not(windows))]
const TOR_EXE_NAME: &str = "tor";

#[derive(thiserror::Error, Debug)]
pub enum Error {
	#[error("Tor process error, {0}")]
	Process(String),
	#[error("Tor IO error, {0}, {1}")]
	IO(String, io::Error),
	#[error("Tor PID error, {0}")]
	PID(String),
	#[error("Tor Reported Error {0}, and warnings: {1:?}")]
	Tor(String, Vec<String>),
	#[error("Tor invalid log line: {0}")]
	InvalidLogLine(String),
	#[error("Tor invalid bootstrap line: {0}")]
	InvalidBootstrapLine(String),
	#[error("Tor regex error {0}, {1}")]
	Regex(String, regex::Error),
	#[error("Tor process not running")]
	ProcessNotStarted,
	#[error("Waiting for Tor respond timeout")]
	Timeout,
}

#[cfg(windows)]
fn get_process(pid: i32) -> Process {
	Process::new(pid as usize, None, 0)
}

#[cfg(not(windows))]
fn get_process(pid: i32) -> Process {
	Process::new(pid, None, 0)
}

pub struct TorProcess {
	tor_cmd: String,
	args: Vec<String>,
	torrc_path: Option<String>,
	completion_percent: u8,
	timeout: u32,
	working_dir: Option<String>,
	pub stdout: Option<BufReader<ChildStdout>>,
	pub process: Option<Child>,
}

impl TorProcess {
	pub fn new() -> Self {
		TorProcess {
			tor_cmd: Self::get_tor_cmd(),
			args: vec![],
			torrc_path: None,
			completion_percent: 100 as u8,
			timeout: 0 as u32,
			working_dir: None,
			stdout: None,
			process: None,
		}
	}

	fn get_tor_cmd() -> String {
		let tor_exe_env = Self::getenv("TOR_EXE_NAME");
		if tor_exe_env.is_some() {
			tor_exe_env.unwrap()
		} else {
			TOR_EXE_NAME.to_string()
		}
	}

	fn getenv(key: &str) -> Option<String> {
		match std::env::var(key) {
			Ok(val) => Some(val),
			Err(_) => None,
		}
	}

	pub fn tor_cmd(&mut self, tor_cmd: &str) -> &mut Self {
		self.tor_cmd = tor_cmd.to_string();
		self
	}

	pub fn torrc_path(&mut self, torrc_path: &str) -> &mut Self {
		self.torrc_path = Some(torrc_path.to_string());
		self
	}

	pub fn arg(&mut self, arg: String) -> &mut Self {
		self.args.push(arg);
		self
	}

	pub fn args(&mut self, args: Vec<String>) -> &mut Self {
		for arg in args {
			self.arg(arg);
		}
		self
	}

	pub fn completion_percent(&mut self, completion_percent: u8) -> &mut Self {
		self.completion_percent = completion_percent;
		self
	}

	pub fn timeout(&mut self, timeout: u32) -> &mut Self {
		self.timeout = timeout;
		self
	}

	pub fn working_dir(&mut self, dir: &str) -> &mut Self {
		self.working_dir = Some(dir.to_string());
		self
	}

	// The tor process will have its stdout piped, so if the stdout lines are not consumed they
	// will keep accumulating over time, increasing the consumed memory.
	pub fn launch(&mut self) -> Result<&mut Self, Error> {
		let mut tor = Command::new(&self.tor_cmd);

		if let Some(ref d) = self.working_dir {
			tor.current_dir(&d);
			let pid_file_name = format!("{}{}pid", d, MAIN_SEPARATOR);
			// kill off PID if its already running
			if Path::new(&pid_file_name).exists() {
				let pid = fs::read_to_string(&pid_file_name).map_err(|err| {
					Error::IO(
						format!("Unable to read from pid file {}", pid_file_name),
						err,
					)
				})?;
				let pid = pid.parse::<i32>().map_err(|err| {
					Error::PID(format!("Pid value {} is invalid, {:?}", pid, err))
				})?;
				let process = get_process(pid);
				let _ = process.kill(Signal::Kill);
			}
		}
		if let Some(ref torrc_path) = self.torrc_path {
			tor.args(&vec!["-f", torrc_path]);
		}
		let mut tor_process = tor
			.args(&self.args)
			.stdin(Stdio::piped())
			.stdout(Stdio::piped())
			.stderr(Stdio::null())
			.spawn()
			.map_err(|err| {
				let msg = format!("Tor executable (`{}`) not found. Please ensure Tor is installed and on the path: {:?}", err, Self::get_tor_cmd());
				Error::Process(msg)
			})?;

		if let Some(ref d) = self.working_dir {
			// split out the process id, so if we don't exit cleanly
			// we can take it down on the next run
			let pid_file_name = format!("{}{}pid", d, MAIN_SEPARATOR);
			let mut file = File::create(pid_file_name.clone()).map_err(|err| {
				Error::IO(format!("Unable to create pid file {}", pid_file_name), err)
			})?;
			file.write_all(format!("{}", tor_process.id()).as_bytes())
				.map_err(|err| {
					Error::IO(format!("Unable to update pid file {}", pid_file_name), err)
				})?;
		}

		let stdout = BufReader::new(tor_process.stdout.take().unwrap());

		self.process = Some(tor_process);
		let completion_percent = self.completion_percent;

		let (stdout_tx, stdout_rx) = channel();
		let stdout_timeout_tx = stdout_tx.clone();

		let timer = timer::Timer::new();
		let _guard =
			timer.schedule_with_delay(chrono::Duration::seconds(self.timeout as i64), move || {
				stdout_timeout_tx.send(Err(Error::Timeout)).unwrap_or(());
			});
		let stdout_thread = thread::spawn(move || {
			let stdout = Self::parse_tor_stdout(stdout, completion_percent);
			if stdout.is_ok() {
				stdout_tx.send(Ok(())).unwrap_or(());
			} else {
				stdout_tx.send(Err(Error::ProcessNotStarted)).unwrap();
			}
			// now we start reading again forever so buffers don't fill
			let _ = Self::parse_tor_stdout(stdout.unwrap(), u8::max_value());
		});
		match stdout_rx.recv().unwrap() {
			Ok(()) => Ok(self),
			Err(err) => {
				self.kill().unwrap_or(());
				stdout_thread.join().unwrap();
				Err(err)
			}
		}
	}

	fn parse_tor_stdout(
		mut stdout: BufReader<ChildStdout>,
		completion_perc: u8,
	) -> Result<BufReader<ChildStdout>, Error> {
		let re_bootstrap = Regex::new(r"^\[notice\] Bootstrapped (?P<perc>[0-9]+)%(.*): ")
			.map_err(|err| Error::Regex("Failed to parse Tor output".to_string(), err))?;

		let timestamp_len = "May 16 02:50:08.792".len();
		let mut warnings = Vec::new();
		let mut raw_line = String::new();

		while stdout
			.read_line(&mut raw_line)
			.map_err(|err| Error::Process(format!("Unable to parse Tor output, {}", err)))?
			> 0
		{
			{
				if completion_perc == u8::max_value() {
					continue;
				} // we just keep consuming the lines.
				if raw_line.len() < timestamp_len + 1 {
					return Err(Error::InvalidLogLine(raw_line));
				}
				let timestamp = &raw_line[..timestamp_len];
				let line = &raw_line[timestamp_len + 1..raw_line.len() - 1];
				debug!("{} {}", timestamp, line);
				match line.split(' ').nth(0) {
					Some("[notice]") => {
						if let Some("Bootstrapped") = line.split(' ').nth(1) {
							let perc = re_bootstrap
								.captures(line)
								.and_then(|c| c.name("perc"))
								.and_then(|pc| pc.as_str().parse::<u8>().ok())
								.ok_or_else(|| Error::InvalidBootstrapLine(line.to_string()))?;
							if perc >= completion_perc {
								break;
							}
						}
					}
					Some("[warn]") => warnings.push(line.to_string()),
					Some("[err]") => return Err(Error::Tor(line.to_string(), warnings)),
					_ => (),
				}
			}
			raw_line.clear();
		}
		Ok(stdout)
	}

	pub fn kill(&mut self) -> Result<(), Error> {
		if let Some(ref mut process) = self.process {
			Ok(process
				.kill()
				.map_err(|err| Error::Process(format!("Fail to kill Tor process, {}", err)))?)
		} else {
			Err(Error::ProcessNotStarted)
		}
	}
}

impl Drop for TorProcess {
	// kill the child
	fn drop(&mut self) {
		trace!("DROPPING TOR PROCESS");
		self.kill().unwrap_or(());
	}
}
