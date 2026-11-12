# Release 7.2.0

## New features and changes

- Add coinbase input/state binding to prevent input substitution. Activation: mainnet block 3,680,000 (December 1 2026); floonet block 1,748,700. Mining requires a wallet supporting `binding_digest` and `coinbase_opening`, even before activation.
- Rework header, block and PIBD synchronization to verify that data from peers advances the blockchain and ban dishonest peers.
- Add `testmempoolaccept` RPC to check unsigned transaction metadata, dependencies and timelocks without publishing transactions.
- Replace `webtunnel_bridge` with `tor_bridge` for custom bridges, transports and SOCKS/HTTP proxies. Tor connects directly by default; transport helpers must be installed separately.
- Upgrade Arti (Tor embedded client) to latest 0.48.

## Fixed issues

- Use compact block announcements on both mining and non-mining nodes to improve network efficiency and miner privacy.
- Avoid repeated full-chain validation during startup and synchronization.
- Preserve sync progress across reorgs and reconnects; correctly track obsolete requests and delayed responses.
- Verify peers' advertised height and difficulty together; recover from unsupported header branches without discarding stored blocks.
- Improve outbound peer rotation and reconnect handling, preferring peers that support coinbase binding.
- Use adaptive request timeouts and disconnect unresponsive peers instead of banning them for timeouts.
- Fix pruning and storage flush handling to preserve bitmap and file consistency after reopening or interrupted writes.
- Make height-based block, header and output API queries follow the active body chain during synchronization and reorgs.
- Prevent mining template rebuilds from overwriting pending coinbase outputs when fees or height change.
- Bound mining transaction-selection work and perform selection outside the transaction-pool lock.
- Reject duplicate Stratum shares, strengthen abuse limits and promptly release stalled worker connections.
- Limit Dandelion expiry processing and avoid repeated validation of unchanged pool transactions.
- Return a clear error when a submitted transaction is already confirmed.
- Fix recovery of height-tagged rangeproofs and zero-value outputs through view keys.
- Protect `mwc clean` with the database lock and validate API secret files when using `--config_file`.
- Handle invalid UTF-8 command-line arguments and fix Ctrl+C shutdown during Tor startup.
- Fix terminal rendering of Slatepack QR codes.
