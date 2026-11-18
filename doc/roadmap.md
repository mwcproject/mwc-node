The MWC network was launched in November 2019.

This roadmap shows where MWC has been and where it plans to go. If you are a skilled developer then please jump in and help make it happen!

# Roadmap
Listed in order of priority. If you want to help please contact us in discord.

1. Additional exchange integrations.
2. Ongoing AI code audits of mwc-node, mwc-wallet and their dependencies.
3. Desktop wallet: mwc-qt-wallet feature upgrades built on its embedded architecture (mwc-node, mwc-wallet and Tor running in a single multi-threaded process).
4. Mining: Stratum protocol upgrades for miners and mining pools.
5. Mobile: continued enhancements to the full archival node running on mobile, along with mobile wallet updates.

There are many potential places development resources can be allocated. They will be chosen based on market needs. Highest priority will be given to requests that primarily benefit and come from the buyers and hodlers of last resort.

# Scheduled
- 12/01/2026 - Coinbase input binding activates at mainnet block 3,680,000 (mwc-node 7.2.0). Miners need a wallet that supports `binding_digest` and `coinbase_opening`.

# Completed

## 2026
- 11/14/2026 - mwc-node 7.2.0: coinbase input binding to prevent input substitution; header, block and PIBD sync verify that peer data advances the chain and ban dishonest peers; `testmempoolaccept` RPC; custom Tor bridges, transports and proxies.
- 11/14/2026 - mwc-wallet 7.0.0 passed a code audit.
- 08/25/2026 - mwc-node 7.1.0: critical performance fixes and additional audit findings addressed.
- 07/31/2026 - mwc-node 7.0.0 passed a code audit (secp256k1-zkp hardening, checked math and conversions). Sync uses all CPU cores, data directory restricted to owner-only permissions, Tor enabled by default.
- 03/15/2026 - mwc-node and mwc-wallet 6.0.1: embedded Tor client (Arti) enabled by default; node and wallet can be built as libraries with a C interface, including multiple instances in parallel.
- 03/15/2026 - QT wallet 2.0.1: multi-threaded architecture with embedded node, wallet and Tor; uses a public node while the embedded node syncs; self-contained Linux installer for cold wallet setups.

## 2025
- 09/13/2025 - QT wallet 1.2.15: simplified Slatepack-first UI, cold wallet workflow fixes.
- 09/09/2025 - mwc-wallet 5.3.9: transaction sessions to prevent transaction data leaks, improved slate and transaction proof validation.
- 08/28/2025 - mwc-node 5.3.10: offline mode for cold wallet setups, transaction fee limits.
- 07/19/2025 - Base transaction fee lowered to 0.000001 MWC (no hard fork required).
- 07/11/2025 - mwc-metal-miner 1.0.0, a GPU miner for Apple Silicon.
- 07/06/2025 - Floonet faucet for developers (mwc-wallet 5.3.7).
- 04/15/2025 - Wallet optimizations for high transaction volume (mining pools and exchanges): partitioned storage, faster transaction building, late-lock fee fixes.
- 01/26/2025 - Node stability and scalability improvements; Apple Silicon binaries.
- 01/06/2025 - mwc-node 5.3.6 fast sync: parallel header download (PIBD), improved peer discovery.
- 2025 - Mobile node, as part of MWC Locker.

## 2024
- 10/04/2024 - Viewing key and ownership proofs (mwc-wallet 5.3.3, QT wallet 1.2.9). QT wallet supports 12, 15, 18, 21 and 24 word passphrases and Tor bridges.
- 09/05/2024 - mwc-wallet 5.3.1: Tor obfs4 and Snowflake bridges, Slatepack QR codes, "reverted" transaction status, send max.
- 08/16/2024 - Rebase to Grin 5.3 (mwc-node 5.3.2) with PIBD fast sync.

## 2022
- 03/31/2022 - NIT scheme security.

## 2021
- 12/29/2021 - Atomic swaps for ETH and ERC-20 tokens.
- 05/30/2021 - Mobile wallet, Android v1.
- 05/20/2021 - Decentralized exchange.
- 03/20/2021 - Atomic swaps for more coins (LTC, ZCash, Dash, Doge).
- 03/20/2021 - Replay attack implementation (The feature will be activated with NIT).

## 2020
- 12/30/2020 - Mwc rebase.
- 12/16/2020 - MWC/BTC & MWC/BCH atomic swaps.
- 10/26/2020 - All funds completely distributed to the MWC hodlers.
- MWCMQS support in mwc-wallet.
- TOR support in all wallets and nodes.
- 08/03/2020 - TOR inbound connections (mwc-node 4.0.0-beta.1).
- 07/04/2020 - TOR outbound connections (mwc-node 3.2.3).
- 06/19/2020 - TOR transactions (QT wallet 1.0.22).
- 04/07/2020 - HODL Program registration (QT 1.0.15).
- 01/22/2020 - Mwc 3.0 rebase (mwc-node 3.0.0).
- 01/21/2020 - MWC CVE patched.

## 2019
- 12/21/2019 - MWC QT wallet cold storage implementation (QT 1.0.11).
- 11/11/2019 - Mainnet launch.
- 10/14/2019 - BTC/MWC atomic swap completed on testnet.

# Initial stock distribution

Funds distribution | Completed at Height | Date | Coins claimed | Total claimed | Announcements
--- | --- | --- | --- | --- | --- |
AIRDROP to Bitcoin HODLers	| | 1/2/20 | 5,400,037.41 | 5,400,037.41 | https://www.mwc.mw/mimble-wimble-coin-articles/claims-for-airdrop-closed |
Claim 1 to MWC hodlers (Hodl program) | 305,000 | 6/11/20 | 7,699.73 | 5,407,737.14 | https://www.mwc.mw/mimble-wimble-coin-articles/hodl-program-status-update |
Claim 2 to MWC hodlers (Hodl program) | 314,760 | 6/18/20 | 774,065.02 | 6,181,802.16 | https://www.mwc.mw/mimble-wimble-coin-articles/hodl-program-status-update
Claim 3 to MWC hodlers (Hodl program + some unclaimed airdrop) | 330,000 | 6/29/20 | 1,491,584.84 | 7,673,387.00 | https://blockfolio.com/coin/MWC_2/signal/GlEchsHvsn
Claim 4 to MWC hodlers (Remaining Dev fund + remaining unclaimed airdrop) | 471,000 | 10/5/20 | 2,261,046.00 | 9,934,433.00 | https://www.mwc.mw/mimble-wimble-coin-articles/mwc-decentralization-distribution-of-dev-fund-and-unclaimed-airdrop-fund
Claim 5 to MWC hodlers (Unclaimed from claim 4)	| 500,000 |	10/26/20 | 32,734.00 | 9,967,167.00 | https://www.mwc.mw/mimble-wimble-coin-articles/update-on-the-last-dev-fund-distribution
Unclaimed (returned to Dev fund) | | | 32,833.00 | 10,000,000.00 |
					
- Dev fund was registered for the HODL distribution 1,2,3.
- All MWC premined funds (Airdrop, HODL and Dev fund) are completely distributed to MWC hodlers.

# PoW Distribution

| Coin | Block #    | Date             | Coins per Block | Coins per Day | Circulating Supply | Stock to Flow | Monetary Inflation |
|------|------------|------------------|------------------|----------------|---------------------|----------------|---------------------|
| MWC  | 0          | November 11, 2019| 2.381            | 3,428.6        | 10,000,000          | 8              | 12.51%              |
| MWC  | 212,580    | April 7, 2020    | 0.600            | 864.0          | 10,506,143          | 33             | 3.002%              |
| MWC  | 385,380    | August 7, 2020   | 0.450            | 648.0          | 10,609,823          | 45             | 2.229%              |
| MWC  | 471,780    | October 7, 2020  | 0.300            | 432.0          | 10,648,703          | 68             | 1.481%              |
| MWC  | 644,580    | February 7, 2021 | 0.250            | 360.0          | 10,700,543          | 81             | 1.228%              |
| MWC  | 903,780    | August 7, 2021   | 0.200            | 288.0          | 10,765,343          | 102            | 0.976%              |
| MWC  | 1,162,980  | February 7, 2022 | 0.150            | 216.0          | 10,817,183          | 137            | 0.729%              |
| MWC  | 1,687,140  | February 7, 2023 | 0.100            | 144.0          | 10,895,807          | 207            | 0.482%              |
| MWC  | 2,221,300  | February 7, 2024 | 0.050            | 72.0           | 10,949,223          | 417            | 0.240%              |
| MWC  | 5,356,260  | February 7, 2030 | 0.025            | 36.0           | 11,105,971          | 845            | 0.118%              |
| MWC  | 10,597,860 | February 7, 2040 | 0.010            | 14.4           | 11,237,011          | 2,138          | 0.047%              |
| MWC  | 886,947,008| Year 3707        | 0                | -              | 20,000,000          | -              | -                   |


**Development is solely financed by donations.**
					
					
