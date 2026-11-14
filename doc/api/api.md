# Node APIs

The node API starts with the server. Default listen addresses are
`127.0.0.1:3413` on mainnet and `127.0.0.1:13413` on Floonet; configuration can
override them. The current router is [api/src/handlers.rs](../../api/src/handlers.rs).

## Authentication

HTTP Basic authentication uses a network-dependent username:

| Network | Username |
| --- | --- |
| Mainnet | `mwcmain` |
| Floonet | `mwcfloo` |
| Other/test contexts | `mwc` |

The configured `.api_secret` protects owner and Stratum administration routes.
The separately configured `.foreign_api_secret` protects
`/v2/foreign`. Middleware is installed when the corresponding secret is
configured. Use the right secret for the endpoint; do not substitute the
wallet owner's `.owner_api_secret`.

## JSON-RPC routes

- `/v2/owner`: node administration, chain status and peer management.
- `/v2/foreign`: wallet-facing chain queries and transaction submission.
- `/v2/stratum`: Stratum administration API, separate from the miner's Stratum socket.

The method definitions are in [owner_rpc.rs](../../api/src/owner_rpc.rs),
[foreign_rpc.rs](../../api/src/foreign_rpc.rs) and
[stratum_rpc.rs](../../api/src/stratum_rpc.rs). Generate documentation from this
checkout with `cargo doc --no-deps -p mwc_api` to match the exact implementation.
Do not assume a separately published `docs.rs/latest` version matches it.

## Embedded calls

An embedding application can initialize the in-process router through
`init_call_api` and call `process_api_call`; the returned `response` is a string
containing the route response. The outer C ABI success envelope and inner
JSON-RPC result/error are distinct. Non-success HTTP status becomes an outer
error. See the [C ABI specification](../mwc_lib_specification.md).
