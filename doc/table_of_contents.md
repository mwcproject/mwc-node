# Node documentation

## Build, operate and integrate

- [Build and run](build.md)
- [Code and workspace structure](code_structure.md)
- [HTTP APIs and authentication](api/api.md)
- [Embedded node C ABI](mwc_lib_specification.md)
- [Tor configuration](tor_inbound_feature.md)
- [Chain synchronization and PIBD](chain/chain_sync.md)
- [Exchange integration recommendations](exchange_recommendations.md)
- [Offline wallet/node workflow](offline_wallet.md)
- Mining setup: [Linux](mining/install_linux.md), [macOS](mining/Install_mac.md), [Windows](mining/install_windows.md)
- [Stratum protocol](stratum.md) and [pool operations](stratum_for_pools.md)

## Protocol and implementation background

- [Introduction](intro.md)
- [Blocks and headers](chain/blocks_and_headers.md)
- [Validation logic](validation/validation_logic.md)
- [Transaction pool](internal/pool.md) and [Dandelion](dandelion/dandelion.md)
- [Merkle trees](merkle.md), [MMRs](mmr.md), [pruning](pruning.md), [state](state.md)
- [Rangeproof format](rangeproof_byte_format.md)
- [Coinbase maturity](coinbase_maturity.md) and [replay mitigation](replay_attack_mitigation.md)
- [Peer protocol](p2p/p2p_protocol.md)

Concept/design papers explain mechanisms, but may simplify consensus equations
or describe proposals. Use the linked implementation and tests for exact rules.

## Historical and versioned material

[Release notes](releases/release-7.2.0.md) describe their named version.
[Roadmap](roadmap.md) is historical.
Translations under `translations/` and adjacent `*_KR.md` files were written
for older revisions and have not been brought up to date with these English
build/API/library guides. In particular, old `mwc wallet`, external Tor and
single-ZIP sync examples should not be used for this checkout.

The wallet is maintained in [mwc-wallet](https://github.com/mwcproject/mwc-wallet)
and the desktop UI in [mwc-qt-wallet](https://github.com/mwcproject/mwc-qt-wallet).
