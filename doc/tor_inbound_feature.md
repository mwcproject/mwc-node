# Embedded Tor and peer connections

Current node code uses **Arti** in `p2p/src/tor`. A separate `tor` executable
and the former `socks_port`, `tor_external`, `onion_address` and `socks5addr`
settings are not the current transport configuration.

Generate `mwc-server.toml` with `mwc server config` in a new data directory.
The current node configuration section is:

```toml
[server.tor_config]
tor_enabled = true
```

`TorConfig::is_tor_enabled()` defaults to true when the option is absent.
The server starts embedded Tor and manages its onion service; this is not the
old scheme forwarding a manually configured Tor hidden service to a TCP host.
The wallet uses the same config type under `[tor]` in `mwc-wallet.toml`.

## Bridges, transports and proxies

An optional `tor_bridge` object supports:

- `bridges`: bridge lines with any required transport parameters.
- `transports`: transport definitions with `protocols` and either `path` to a
  managed helper or `proxy_addr` for an existing SOCKS5 transport endpoint.
- `proxy`: an upstream SOCKS4, SOCKS5 or HTTP CONNECT proxy URI.

A managed helper can also specify `arguments` and `run_on_startup`. `path` and
`proxy_addr` are mutually exclusive. Helpers such as webtunnel are separate
executables; their paths must exist on the host. This object is not a switch
to use the removed external-Tor-process implementation.

See [TorConfig and bridge types](../p2p/src/types.rs), the generated
[configuration comments](../config/src/tor_comments.toml), and
[Arti setup](../p2p/src/tor/arti.rs) for validation and supported formats.

## Embedded applications

`start_tor` starts the process-wide runtime; `tor_status` returns `started` and
`healthy`. Peer discovery, listening and synchronization are separate node
service calls. Check their startup results as well as ongoing status.
`shutdown_tor` requests cancellation at application exit and does not mean all
runtime threads have already joined. Its shutdown token is one-way for the
process lifetime. See the [library contract](mwc_lib_specification.md).
