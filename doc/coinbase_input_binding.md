# Coinbase input binding (S2C)

The Coinbase kernel signature commits to the block's exact inputs and its parent's
unspent-output state using sign-to-contract (S2C). This prevents replacing inputs
with a different set having the same commitment sum:

```text
resolved inputs + parent state → digest D → Coinbase kernel signature → kernel root → PoW
```

A public 33-byte opening accompanies the block so validators can check the
commitment. The kernel remains an ordinary valid AggSig signature. Header format,
block weight, and PMMR leaf counts stay unchanged; ordinary Coinbase rangeproofs
and wallet recovery continue to work. Older nodes accept the legacy wire encoding,
making this a soft fork, but cannot enforce the binding or supply its opening.
Independent cryptographic review of S2C and its integration is a release requirement.

## Activation

| Network | First bound block |
| --- | ---: |
| Mainnet | 3,632,000 |
| Floonet | 1,753,000 |
| AutomatedTesting / UserTesting | 4 |

See [consensus.rs](../core/src/consensus.rs). Activated blocks require exactly one
Coinbase output, one Coinbase kernel, and an opening. Parent state comes from the
candidate branch at runtime, including during reorgs; no future checkpoint values
are configured.

## Digest encoding

Defined in [coinbase_binding.rs](../core/src/libtx/coinbase_binding.rs).
`H` is BLAKE2b with a 32-byte output, not truncated BLAKE2b-512. Integers are
unsigned and big-endian; hashes are raw 32-byte values. Domain strings are exact
ASCII bytes without a terminator or length prefix.

```text
record = position:u64 || output_features:u8 || commitment:33

I = H("MWC_CB_BIND_INPUTS_V1" || input_count:u64 || sorted_records)
B = H("MWC_CB_BIND_BITMAP_V1" || parent_output_leaf_count:u64 || packed_bitmap)
D = H("MWC_CB_BIND_CONTEXT_V3" || genesis_hash || parent_hash || height:u64 ||
      I || B || parent_output_leaf_count:u64 || reward:u64)
```

- Resolve the final inputs **after aggregation and cut-through** against the parent
  UTXO set. Sort records by **one-based PMMR leaf position**. Reject duplicate
  positions or commitments. An empty input set has count zero and no records.
- `reward` is the block subsidy plus fees. `parent_output_leaf_count` includes all
  historical output leaves, spent and unspent.
- The bitmap describes the parent **before applying this block**. Bits use
  **zero-based output leaf indexes**, not PMMR positions: unspent = 1, spent = 0.
  Index zero is the high bit of the first byte. Include exactly `ceil(leaf_count/8)`
  bytes, including zero gaps and trailing zeros; unused low bits are zero.

`unspent_bitmap_hash()` streams the ascending indexes from `leaf_idx_iter(0)`
through a 128-byte buffer. It allocates no full bitmap and caches no hash.
PIBD's `BitmapAccumulator` Merkle root is a separate commitment, not this hash.
Do not include the candidate kernel root or block hash in `D`: they depend on the
signature being constructed.

## Mining and wallet RPC

1. Aggregate transactions, perform cut-through, and compute `D` from the final
   inputs and parent state via `Chain::coinbase_binding_for_template()`.
2. Call the existing `/v2/foreign` `build_coinbase` method:

   ```text
   block_fees: { fees, height, key_id, binding_digest: hex64 }
   result.Ok:  { output, kernel, key_id, coinbase_opening: hex66 }
   ```

   `key_id` is optional. The digest and opening are required at **every height**;
   node and wallet must both support this contract before activation too.
3. The wallet calls shared `reward::output_s2c()`: create the ordinary reward
   output and sign the normal Coinbase kernel message while committing to `D`.
   The secret nonce derivation includes `D`, so reusing a reward key for another
   digest changes the nonce. The opening is a public base-nonce point, never a
   secret scalar.
4. The node verifies the returned binding and reward balance. Before activation
   it omits the opening from the block; from activation it includes the opening
   and validates against the final body when setting roots. Discard a template if
   its parent changes; any change to `D` requires another Coinbase request.

Local burn rewards use the same signing function. Invalid or unsupported binding
responses stop mining; connection failures use normal retries. Wallet recovery
uses ordinary proof metadata and needs neither `D` nor a stored digest index.

Entry points: [mine_block.rs](../servers/src/mining/mine_block.rs),
[reward.rs](../core/src/libtx/reward.rs), and in `mwc-wallet`,
`api/src/foreign_rpc.rs`, `libwallet/src/internal/updater.rs`, and
`libwallet/src/api_impl/types.rs` (`BlockFees` / `CbData`).

## Block validation and transport

For activated blocks, `Extension::apply_block()` in
[txhashset.rs](../chain/src/txhashset/txhashset.rs) requires the opening,
resolves inputs, and checks the binding **before changing
the parent UTXO state**. It recomputes `D` and calls `secp::s2c::verify_single()`
for the Coinbase kernel signature and opening. Ordinary sums, signatures,
rangeproofs, maturity, and UTXO checks still apply. Block series and fork replay
use this same path. Changing inputs changes `D`; replacing the signature to match
changes the header's kernel root and invalidates the mined PoW.

`Block` and `CompactBlock` carry `coinbase_opening`; storage keeps it inside the
existing block record. Activated serialization appends its 33 compressed-point
bytes when `block_extra` is enabled. Preactivation encoding and header-only block
hashing stay unchanged. Readers/writers require an explicit `block_extra` flag:
storage passes `true`, network callers use `PeerInfo::is_block_extra()`. Decoding
is strict and never retries a different format.

`Capabilities::BLOCK_EXTRA` (`0x100`) selects the extended encoding using the
existing block message types and protocol version 5. Local nodes always advertise
it. Legacy peers receive encoding without the opening. Every block request
requires a capable supplier, regardless of height. Near the tip, request only
from the announcing peer if capable; otherwise wait for another announcement or
ordinary sync. Normal operation and body sync disconnect incapable outbound
peers without banning them. Header sync and PIBD may use them.

Existing v3 databases preserve preactivation blocks without openings; no block
rewriting or reset is needed, in either archive mode. A populated database missing
the completed `blocks_v3_migrated` flag still resets/resyncs, even before activation,
because obsolete storage formats are no longer migrated. Activated block records
missing their opening also trigger reset/resync. Headers are retained; malformed
records remain errors. See
[store.rs](../chain/src/store.rs), `reset_legacy_blocks()`.

## PIBD and recovery

PIBD keeps its existing segment protocol and validation. After importing height
`H`, ordinary processing of block `H+1` checks its binding against the imported
parent bitmap and leaf count. No block-binding data is added to PIBD.

If `H+1` is activated, retain the selected root's endorsers until the chain advances.
`SyncManager::report_pibd_block()` counts distinct suppliers reporting bad-data
failures for that exact successor matching the canonical header. Normal block
requests and retries apply; suppliers need not be root endorsers. Three failures
ban all root endorsers, including disconnected ones, discard the import, and
restart PIBD. Timeouts and local/recovery errors do not count. A decoded block
missing its opening counts; malformed wire data rejected before block reporting
does not.

**Accepted false-ban risk:** three malicious suppliers can trigger bans of honest
root endorsers. This is a recovery heuristic, not proof that the imported root is
wrong. Different addresses do not guarantee independent suppliers.

Votes and failures are in memory. A restart with an imported head but neither
its block body nor `BODY_TAIL` resets the import and repeats PIBD while retaining headers.
After the first full block is saved, normal restart behavior applies. See
[state_sync.rs](../servers/src/mwc/sync/state_sync.rs) and
[sync_manager.rs](../servers/src/mwc/sync/sync_manager.rs).
