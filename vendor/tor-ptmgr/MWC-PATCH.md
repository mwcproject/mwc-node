# MWC tor-ptmgr patch

This directory vendors `tor-ptmgr` 0.45.0 from crates.io, whose source commit is
`009354f78d1a61214a878d6f1712a50844e6c215`.

## Problem

Upstream 0.45.0 moves the `Child`, its `ChildStdin`, and its blocking stdout
reader into one OS thread. That thread notices that `AsyncPtChild` was dropped
only when it tries to forward another stdout line into the disconnected channel.
After PT negotiation, `webtunnelclient` is normally quiet while waiting for
SOCKS connections, so the blocked stdout read may never return and stdin stays
open. A failed Arti bridge attempt can therefore leave its old
`webtunnelclient` running while subsequent bridges start more instances.

## Exact changes

- [`src/ipc.rs`](src/ipc.rs), `supervise_pt_child`: adds a dedicated process
  supervisor which owns the `Child` and `ChildStdin`, independently of the
  blocking stdout reader. It polls for normal process exit and also waits for an
  explicit shutdown message.
- [`src/ipc.rs`](src/ipc.rs), `AsyncPtChild::new`: leaves only `ChildStdout` in
  the stdout forwarding thread and starts the separate process supervisor with
  `Child` and `ChildStdin`.
- [`src/ipc.rs`](src/ipc.rs), `AsyncPtChild::drop`: sends the explicit shutdown
  message and joins the supervisor. The supervisor closes stdin, waits up to
  `GRACEFUL_EXIT_TIME` (five seconds), then kills and reaps a child which did not
  exit. Joining guarantees that a failed PT is gone before Arti can start the
  next bridge attempt.
- [`src/ipc.rs`](src/ipc.rs),
  `dropping_quiet_child_stops_and_reaps_process`: adds a regression test whose
  child becomes quiet and exits only after stdin EOF. This reproduces the
  lifecycle of `webtunnelclient` after successful PT negotiation.
- [`../../p2p/src/tor/arti.rs`](../../p2p/src/tor/arti.rs),
  `ArtiCore::bootstrap_tor_client`: gives failed Arti runtime destruction ten
  seconds, so the supervisor's bounded five-second graceful/forced shutdown can
  finish before the next bridge is tried.
- [`../../p2p/src/tor/arti.rs`](../../p2p/src/tor/arti.rs),
  `ArtiCore::webtunnel_client_filename`: uses the target platform's executable
  suffix, allowing Windows builds to find the packaged `webtunnelclient.exe`.
- [`../../Cargo.toml`](../../Cargo.toml), `[patch.crates-io]`: redirects
  `tor-ptmgr` to this patched source.

## Resulting process lifecycle

Dropping a failed bridge's `AsyncPtChild` no longer depends on PT output. It
wakes the supervisor immediately, and `webtunnelclient` normally observes stdin
EOF and exits gracefully. If it does not respond, it is killed after five
seconds and then reaped. Only the PT belonging to the selected bridge remains
running.

The override can be removed after an equivalent fix is available in the pinned
Arti release.
