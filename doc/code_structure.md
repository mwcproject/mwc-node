# Node code structure

The [root manifest](../Cargo.toml) defines the node workspace. `Cargo.lock` is
tracked. The wallet is a separate `mwc-wallet` repository; this workspace has
no `mwc wallet` subcommands or wallet seed/database backend.

| Directory | Responsibility |
| --- | --- |
| `src` | `mwc` executable, CLI commands and terminal UI |
| `mwc_crates` | Shared third-party dependencies/re-exports; optional `tui` feature |
| `node_workflow` | Contexts, server lifecycle and embedded API operations |
| `mwc_node_lib` | C ABI and JSON request dispatcher |
| `api` | HTTP routing, authentication and node JSON-RPC handlers |
| `chain` | Block/header validation, chain state, txhashset and synchronization data |
| `config` | Configuration loading, defaults and generated comments |
| `core` | Consensus rules, blocks, transactions, serialization and proof-of-work validation |
| `keychain` | Key derivation and commitment operations |
| `p2p` | Peers, protocol messages and embedded Arti transport |
| `pool` | Transaction/stem pools and admission/reconciliation |
| `servers` | Server orchestration, adapters, synchronization and Stratum service |
| `store` | LMDB and persistent MMR storage |
| `util` | Logging, common helpers and cryptographic dependencies |
| `vendor` | Patched dependency sources selected by the manifest |
| `doc` | Operational guides, protocol explanations and historical material |

The node validates work and offers Stratum jobs; mining workers are provided
by the separate `mwc-miner` project. Old plugin/CPU/GPU build instructions for
miners do not describe this node workspace.

## Data and entry points

By default configuration and data are under `~/.mwc/main` or `~/.mwc/floo`.
`mwc server config` generates a configuration using the current directory;
`db_root` controls the chain-data location. Under that root, chain/peer stores
and txhashset files are managed by the node, not by a wallet seed provider.
Build artifacts go in Cargo's target directory.

For applications embedding the node, `mwc_node_lib` dispatches requests into
`node_workflow`. Allocate a chain context, create a server with a database
root, initialize API dispatch, and explicitly start the services needed by the
application. A cold wallet can use local chain/API functionality without
starting peer discovery, peer listening or synchronization. See the
[library specification](mwc_lib_specification.md).

See [building/running](build.md), [synchronization](chain/chain_sync.md), and
[API routing](api/api.md). Translations of the previous structure describe
older code and may not include these workspace/lifecycle changes.
