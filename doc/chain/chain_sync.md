# Chain synchronization

Synchronization brings a new or returning MWC node up to the chain available
from its peers. It includes finding and validating headers, obtaining chain
state, downloading missing block bodies, and following new blocks and forks.
The same machinery serves the standalone node and an embedded node whose
application has started networking and synchronization. Wallet scanning is a
separate operation against the node's validated chain.

The [SyncManager](../../servers/src/mwc/sync/sync_manager.rs) coordinates the
downloads. The [sync runner](../../servers/src/mwc/sync/syncer.rs) repeats the
work, publishes status and requests peers with the capabilities needed by the
current stage. Existing local progress determines which stages are necessary.

## Chain data and synchronization modes

A node starts with the genesis block for its configured network. It maintains
two tips that can advance at different rates:

- **Header tip:** the selected chain of validated block headers. Headers contain
  ancestry, proof of work, accumulated difficulty, state roots and MMR sizes.
- **Chain tip, or body tip:** the point reached by the local transaction state.
  During initial synchronization this can be far behind the header tip. A
  validated PIBD (Parallel Initial Block Download) import advances it to the snapshot height; subsequent block
  processing advances it further.

The **txhashset** is the output, rangeproof and transaction-kernel state held in
Merkle mountain ranges (MMRs), together with the information identifying unspent
outputs. The output MMR commits to output history, including hashes retained
after pruning. Its root alone is not a commitment to which leaves are currently
unspent. The output bitmap and the additional state checks therefore matter.

The node selects chains using validated accumulated work. A peer advertising a
large height or difficulty has made a claim; that advertisement is not itself
validated chain data.

| Mode | Initial state and block download | Retained history |
| --- | --- | --- |
| Normal node, `archive_mode = false` (default) | Use PIBD when the local fork point is behind the selected archive height, then download subsequent blocks. Otherwise reuse local state. | Retain headers, kernels, required output/rangeproof state and a recent block-body window; older data is subject to pruning. |
| Archive node, `archive_mode = true` | Skip PIBD **state import** and obtain missing block bodies, starting from genesis for a new database. Header synchronization still applies. | Retain historical full block bodies for archival use and serving other nodes. State-file compaction can still run. |

Set `archive_mode` in `[server]` in `mwc-server.toml`. Choose archive mode before
initial synchronization if full block history is required: changing the setting
does not recreate block bodies already omitted by a snapshot or deleted by
pruning. Archive synchronization needs more download time and disk space, and
requires peers that can serve old blocks.

PIBD (Parallel Initial Block Download) downloads pieces
of a recent txhashset from multiple peers in parallel. The node verifies the
pieces and the reconstructed state, then downloads the blocks after that
snapshot to reach the current tip. This avoids downloading every historical
block body. Both modes perform validation; their retained history and bootstrap
assumptions differ.

## Overall workflow

1. Open and recover the local chain database, validate its state and rebuild
   required indexes. Startup validation can take time before network downloads
   begin.
2. Connect to peers on the configured network and obtain usable height/work
   advertisements and capabilities.
3. Where bootstrap is needed, select an archive period and synchronize the
   headers leading to it. Header-hash checkpoints allow parallel header downloads.
4. If local state is insufficient and archive mode is disabled, download and
   validate a PIBD snapshot.
5. Once state is ready, run ordinary header and block-body synchronization.
   Header and body downloads can proceed concurrently; bodies are applied in
   chain order.
6. Continue following announcements and checking peer tips. Handle competing
   branches, retry missing data and compact eligible stored data.

Some steps are skipped on a restart with usable local data. Completion of a
download phase does not imply completion of its validation phase.

## Peers and the archive point

### Required peer capabilities

The downloaders choose peers according to the data being requested:

| Capability | Purpose |
| --- | --- |
| `HEADERS_HASH` | Supply the checkpoint-hash root and segments used to accelerate header synchronization. |
| `HEADER_HIST` | Supply block headers. |
| `PIBD_HIST` | Supply the snapshot bitmap and txhashset segments. |
| `BLOCK_HIST` | Supply block bodies older than the normal retained-body horizon. |
| `BLOCK_EXTRA` | Supply the additional block data required by activated coinbase-binding rules. |

The startup wait initially looks for three outbound peers with at least the
local chain's work, but that wait has a timeout. It does not replace the quorum
requirements of the later bootstrap stages. A node can have connected peers
and still be waiting for suitable suppliers or enough matching responses.

Archive-target and header-hash discovery use outbound peers with known tips.
Snapshot discovery uses eligible `PIBD_HIST` peers in the selected archive
period, preferring outbound peers when any are available. Ordinary block
download also checks whether a peer's advertised height/work matches the
selected header chain and whether it can serve the requested block.

### Selecting a common snapshot height

Peers offer snapshots at common archive heights so that segments from different
suppliers refer to the same state. For an advertised height `H`, the node computes:

```text
A = max(H - state_sync_threshold, 0)
archive_height = A - (A % txhashset_archive_interval)
```

Current mainnet and Floonet values are:

| Parameter | Blocks | Purpose |
| --- | ---: | --- |
| State-sync threshold | 2,880 | Keep the snapshot roughly two days behind the advertised tip. |
| Archive interval | 720 | Round snapshots to a common half-day boundary. |
| Cut-through horizon | 10,080 | Retain roughly a week of recent block history for ordinary catch-up and rewinds. |

These times assume the target one-minute block interval; the rules use block
counts. Automated and user-testing networks have smaller values. The archive
point and pruning horizon are different parameters. They are defined in
[consensus](../../core/src/consensus.rs) and
[global network parameters](../../core/src/global.rs); the calculation is in
[Chain::height_2_archive_height](../../chain/src/chain.rs).

Bootstrap target selection requires a strict majority of the eligible outbound
`HEADERS_HASH` peers to advertise the same archive height, with at least two
matching peers. The target height is the highest advertised height within that
selected group. Header-hash root selection and snapshot bitmap-root selection
have their own quorum checks, also requiring at least two matching responses
and a strict majority of their eligible peer sets.

These are local peer-agreement rules, not blockchain consensus. When agreement
is insufficient, the node waits or retries discovery. It does not repeatedly
move an arbitrary horizon backward until all peers agree, and it does not ask
the operator to approve a block hash.

## Header synchronization

### Header hashes and parallel bootstrap

The node first requests a header-checkpoint root for the selected archive
height. After selecting a root, it downloads checkpoint-hash segments and
checks their Merkle proofs. It then requests batches of actual headers from
peers that agreed with that root.

Batches must match the requested range and checkpoint boundaries, contain
consecutive heights, and have valid previous-header links. Responses can arrive
out of order, but the downloader applies the next contiguous batch. Applying
the headers runs chain validation, including proof of work, difficulty and
header rules. Peer agreement and checkpoint proofs do not replace those checks.

Header-checkpoint roots and the snapshot's output-bitmap root are separate
commitments. An agreed header-hash root does not establish that a later state
snapshot is valid.

### Ordinary headers and new branches

Once the state gate is satisfied, ordinary header synchronization uses locators
containing hashes from progressively earlier heights to find common ancestry.
It requests headers for greater advertised work and also investigates
equal-work advertisements with a different height. Responses must substantiate
the peer's height/work claim.

A direct-extension header announcement can advance the header chain after
validation. An announcement on another branch first requires its ancestry to
be downloaded. Body downloads continue while ordinary headers are being
obtained; a visible header-sync stage does not suspend body work.

Implementation:
[header-hash discovery](../../servers/src/mwc/sync/header_pibd_hashes_sync.rs),
[checkpoint headers](../../servers/src/mwc/sync/header_pibd_sync.rs),
[ordinary headers](../../servers/src/mwc/sync/header_sync.rs), and
[header validation](../../chain/src/pipe.rs).

## PIBD state synchronization

### When a snapshot is needed

The state downloader checks the selected archive height and the fork point
between the local body chain and selected header chain. If the local state
already covers that archive point, ordinary block download can continue.
An archive height of zero uses genesis state. Archive mode bypasses snapshot
import entirely.

Otherwise, the node needs the validated header at the archive height and
discovers suppliers for that exact snapshot. A changed archive header or
invalidated local state causes obsolete snapshot work to be discarded.

### Discovering and downloading the snapshot

`StartPibdSyncRequest` identifies the archive height and hash. Suppliers return
`PibdSyncState`; a peer offering a different archive point can respond with
`HasAnotherArchiveHeader`. The bitmap root selected by quorum identifies the
unspent-output bitmap to reconstruct.

The node downloads four types of segments:

| Segment | Contents and verification |
| --- | --- |
| Output bitmap | Positions of unspent output leaves, checked against the selected bitmap root. |
| Outputs | Output identifiers and commitments, with proofs against the archive header's output root. |
| Rangeproofs | Proofs for retained outputs, with segment proofs against the archive header's rangeproof root. |
| Kernels | Transaction-kernel history, with segment proofs against the archive header's kernel root. |

The bitmap is reconstructed first because it determines the required output
and rangeproof segments. Pruned regions can be represented by authenticated
hashes rather than spent output data. Kernels are retained as history.

Requests are distributed across eligible suppliers. The downloader bounds
outstanding work and buffered responses, retries expired requests and applies
authenticated data in the required order. Responses must match active segment
tasks, the current archive header and the supplier's bitmap-root endorsement.
Responses for obsolete snapshot sessions are discarded.

Buffer sizes and request limits adapt to available memory, CPU count and
network observations. These are implementation parameters in
[PibdParams](../../chain/src/pibd_params.rs), not a set of required user settings.

The current network protocol does **not** fall back to downloading a txhashset
ZIP when PIBD peers are unavailable. The old archive request/response messages
are rejected by the [protocol handler](../../p2p/src/protocol.rs).

### Validation and installation

Receiving all segments is only the start of final state validation. The node:

1. Reconstructs leaf sets and checks state roots against the archive header.
2. Checks the kernel history against the headers, including historical kernel
   roots and contextual kernel-position rules.
3. Validates the MMR structure, sizes and output/rangeproof consistency.
4. Checks aggregate output and kernel commitments with the accumulated kernel
   offset and expected issuance. This is more than comparing UTXO commitments
   to a supply number.
5. Verifies unspent-output rangeproofs and kernel signatures.
6. Installs the validated state and rebuilds output and kernel indexes.

The archive header becomes the body tip, but its full block body and the older
block bodies have not been downloaded. The retained-body boundary begins when
subsequent full blocks are saved. Any index based on historical block bodies
has only the coverage provided by those locally retained bodies.

Where coinbase binding is active for the first block after the snapshot, the
node retains the snapshot session's root endorsements while ordinary block
validation checks that successor against the imported state. Acceptance of a
subsequent block ends this recovery tracking. The failure behavior is described
below.

The source of these rules is
[StateSync](../../servers/src/mwc/sync/state_sync.rs),
[Desegmenter](../../chain/src/txhashset/desegmenter.rs), and
[txhashset validation](../../chain/src/txhashset/txhashset.rs).

### Serving other nodes

A normal node can serve PIBD snapshots; serving them does not require archive
mode. The producer prepares state at its current archive height and generates
proof-bearing segments. The receiver must use a consistent archive header and
root across suppliers. Archive mode adds the ability to serve older full block
bodies, which is a different service.

Snapshot generation is implemented by the
[segmenter](../../chain/src/txhashset/segmenter.rs). The request and response
definitions are in [P2P messages](../../p2p/src/msg.rs).

## Block download and following the tip

With state ready, [BodySync](../../servers/src/mwc/sync/body_sync.rs) downloads
missing bodies on the selected header chain. It starts after the imported
snapshot or after the usable local fork point. A new archive node downloads
the bodies from genesis onward.

Requests can run in parallel across peers, but the node validates and applies
bodies in ancestry order. Supplier selection considers the requested height,
the peer's verified height/work advertisement, retained history, protocol
capabilities, latency and outstanding-request capacity. Old bodies require a
`BLOCK_HIST` supplier when normal peers have already pruned them.

Full blocks and reconstructed compact blocks enter the same body-processing
path. A malformed or invalid body does not become accepted state merely
because its header was downloaded earlier. Requests from an obsolete branch
are retired when the selected chain changes.

Once caught up, the node continues requesting new headers and bodies. Normal
operation can include a small moving gap behind peers. Periodic compaction
removes eligible old data according to the node's mode and pruning horizon.

## Forks, failed suppliers and recovery

### Competing chains and missing history

The node validates a competing branch and its work before changing selected
chain state. When the required data is retained, it can rewind to common
ancestry and apply the new branch. For state-sync eligibility, the common fork
point matters: a high local body height on a different branch is not sufficient.

A fork older than locally retained history cannot be handled by assuming the
missing bodies or spent-output data still exist. Catch-up may require historical
block suppliers or a new state import. During state selection, a fork point
below the selected archive height can trigger PIBD on a normal node.

Archive mode retains block bodies but does not remove the chain-processing
rewind horizon. A `RewindBeyondHorizon` error is a local recovery limitation,
not evidence that the supplier sent an invalid block.

There is a current limitation after a process has marked PIBD/state setup
complete: ordinary body sync handles subsequent catch-up without automatically
re-entering PIBD, including when a later fork needs older state. If that running
node loses connectivity long enough to fall outside peers' retained history,
it needs a historical-block supplier or a
restart so state-sync eligibility is evaluated again. A restart can therefore
help in this case without deleting the chain database.

### Unsupported header branches

The node can release a header-only branch whose suppliers have disappeared,
without discarding accepted block bodies. During normal operation this fallback
requires at least two outbound peers with known tips, all advertising less work
than the selected header tip. The fallback preserves the accepted body chain
and can retain a supported header prefix. Startup also performs a local header
fallback after chain validation. Initial header progress is preserved while
the body chain is still at genesis.

### Timeouts, disagreement and invalid data

Expired requests are retried. Repeated nonresponses can make a peer defunct and
disconnect it; a timeout alone is not evidence that its chain data is malicious.
Bad data and explicit session failures follow separate scoring/ban paths.
Reconnects clear old unanswered requests and timeout history.

A split vote for a header-checkpoint root or snapshot bitmap root does not
identify which peer is dishonest. The node waits for usable agreement or
retries discovery rather than treating disagreement itself as proof of fraud.

Final snapshot validation failures take a more conservative recovery path:
the implementation can queue bans for endorsers of the selected bitmap root
and discard the snapshot session before retrying. This includes failures during
leaf-set finalization or complete-state validation; the code does not prove
that every such failure was caused by a malicious endorser.

For a retained post-import session, qualifying bad-data failures from three
**distinct suppliers** for the exact first successor block trigger the same
session recovery. The block must match the selected header and extend the
imported head. Timeouts, known-block results and errors requiring local chain
recovery do not count. Suppliers need not be the snapshot-root endorsers.

This is a recovery heuristic with an explicit false-ban risk: malicious body
suppliers can cause honest root endorsers to be penalized. Successful chain
advancement clears the retained session and its failure count. See
[report_block_result](../../servers/src/mwc/sync/sync_manager.rs) and
[peer scoring](../../servers/src/mwc/sync/sync_peers.rs).

### Restarting after an interruption

Chain writes and resets use persistent recovery markers. Startup reconciles
the committed database and MMR state before synchronization uses them. A
partially downloaded or partially installed snapshot is not treated as valid
just because files exist on disk.

Snapshot endorsements and request tracking are in memory. If the process
restarts after importing a snapshot but before saving a subsequent full block,
the imported head has neither its full block body nor an established body tail.
Startup resets that imported body state and repeats PIBD while preserving
headers through the recovery path. Once a subsequent full block is saved,
ordinary restart behavior applies. Interrupted downloads are therefore not
guaranteed to resume at their previous segment count.

Local storage failures and corrupt retained records can require recovery or
prevent startup. They must not be interpreted simply as a lack of peers.
[Chain initialization and recovery](../../chain/src/chain.rs) implement these
checks.

## Security assumptions

Full-history synchronization verifies historical block bodies; PIBD reconstructs
and validates state without retaining all of those bodies. PIBD still requires
validated headers, authenticated segments and full state checks. It does not
provide the same historical-body archive.

Peer quorums are formed from the node's eligible connections, not a global vote.
Different addresses do not guarantee independently operated peers. One honest
peer is not necessarily enough to win a local quorum. Isolation or a Sybil
attack can stall synchronization or expose the node only to a stale valid
branch. Proof-of-work and state validation remain necessary even after peers
agree.

An attacker cannot justify an inflated accumulated-difficulty value simply by
advertising it: downloaded headers must satisfy work, linkage and difficulty
rules. Likewise, a forged output, rangeproof or kernel segment must pass its
proof and subsequent validation. The snapshot bitmap's separate commitment
and post-import checks must be considered alongside the header's state roots.

A valid higher-work reorganization can replace recent accepted history. A deep
reorganization can also exceed the data retained by a pruned node. These are
different problems from receiving a malformed segment.

A permanent consensus-rule fork is not resolved by repeatedly choosing an
older snapshot. The node validates using its configured network's genesis and
consensus rules. Peer capabilities describe what data can be exchanged; they
do not make an incompatible chain valid.

## Reading synchronization status

The terminal UI reports header and body tips separately. The HTTP owner API's
`get_status` method at `/v2/owner` returns `sync_status`, `sync_info`, the body
tip and connection count. See [API access and authentication](../api/api.md).

| API status | What the node is doing |
| --- | --- |
| `initial`, `awaiting_peers` | Initializing or waiting for suitable peers/agreement. |
| `header_hash_sync` | Obtaining authenticated header-checkpoint hashes. |
| `header_sync` | Downloading and applying headers. |
| `txhashset_pibd` | Discovering/downloading the snapshot segments. |
| `validating_kernels_history`, `txhashset_kernels_pos_validation` | Checking kernel history and contextual position rules. |
| `txhashset_state_validation` | Checking state structure, roots, sizes, leaf sets and commitment sums; `sync_info.stage` identifies the substage. |
| `txhashset_rangeproofs_validation`, `txhashset_kernels_validation` | Verifying rangeproofs or kernel signatures. |
| `txhashset_output_pos_index_build`, `txhashset_kernel_pos_index_build` | Building the lookup indexes needed to use the imported or recovered state. |
| `body_sync` | Downloading and applying full blocks on the selected header chain. |
| `no_sync` | Normal operation, including following small tip changes. |
| `shutdown` | Stopping the node. |

Progress values are local to each stage. Segment counts are not byte counts,
and download completion does not mean cryptographic validation or index
building has finished. Startup recovery can also display validation stages.

The current tip-distance threshold is ten blocks. The coordinator can keep
`no_sync` while following gaps smaller than ten blocks; the separate
`SyncState::is_syncing()` helper treats a `BodySync` gap of ten blocks or less
as not syncing. Consequently, a displayed "Running" state or a false syncing
flag is not proof of exact equality with every peer's tip. Inspect the actual
tips, work and progress when diagnosing a lagging node.

Status definitions and API mappings are in
[SyncStatus](../../chain/src/types.rs) and the
[status handler](../../api/src/handlers/server_api.rs).

## Diagnosing stalled synchronization

| Observation | What to check |
| --- | --- |
| Connected peers, but still awaiting peers | Required capabilities, known advertised tips, matching archive periods and quorum messages in the logs. A connection count alone does not show supplier eligibility. |
| Header height advances but body height does not | Whether PIBD download, state validation or index rebuilding is still active. Body processing waits for usable state. |
| Snapshot download is complete but progress continues | The validation stage and CPU/disk activity; rangeproof, kernel and index work can be substantial. |
| Repeated segment requests or peer disconnects | Request timeouts, network latency, supplier availability and bad-data messages. The downloaders retry automatically. |
| Old block requests cannot be satisfied | Availability of `BLOCK_HIST` peers; check the prolonged-disconnection limitation above. |
| PIBD starts again after a restart | Whether the prior import was interrupted or had not yet saved its first subsequent full block. |
| Repeated import validation or first-successor failures | The precise validation errors and session-recovery messages; distinguish peer-supplied data failures from storage/recovery errors. |
| Header tip moves backward without losing accepted bodies | The unsupported-header-branch fallback or a change of selected branch. |

Keep the node on the intended network, allow normal peer discovery and use the
logs to identify the current stage before deciding on recovery. A stalled
download alone is not a reason to delete chain files. Build and startup
instructions are in [Build and run](../build.md).
