# Offline wallet transactions

Wallet commands belong to the separate **mwc-wallet** executable. `mwc` is the
node. The Qt desktop wallet also provides Cold Wallet and Online Node modes;
see its [cold-wallet guide](https://github.com/mwcproject/mwc-qt-wallet/blob/master/DOC/cold_wallet.md)
for snapshot export/import and `.mwctx` publication through the GUI.

An offline wallet needs chain data from an online node on the same network to
select unspent outputs and later see confirmations. Stop a node before copying
its database; do not copy a live LMDB/txhashset directory piecemeal. Use the
Qt snapshot workflow or a complete, compatible stopped-node data copy.
Keep the signing machine disconnected and never move its seed to the online node.

## CLI workflow

1. Create a dedicated offline node configuration with `mwc server config`.
   Supply compatible chain data and start it with `mwc server --offline run`.
   Check configured bind addresses and keep the host network isolated.
2. Initialize a wallet in a dedicated directory with `mwc-wallet init --here`.
   (`init -h` is its short form; `init --help` displays help.) Configure the
   wallet to use the local node and its foreign API secret.
3. Exchange transaction Slatepacks/files with the other wallet. Sending creates
   an initial slate; receiving adds the recipient's contribution and returns
   a response to the sender.
4. On the offline sender, finalize the response without publishing:

   ```sh
   mwc-wallet finalize --file response.slatepack --nopost
   ```

5. Transfer the resulting binary transaction from the wallet's
   `wallet_data/saved_txs/<uuid>.mwctx` to the online machine. A configured online
   wallet can publish it to its node with:

   ```sh
   mwc-wallet submit --input transaction.mwctx
   ```

   `submit` accepts a binary `.mwctx`; `post` accepts a finalized slate. Do not
   substitute one format for the other.

6. After mining, refresh the offline node's chain data and scan/update the
   offline wallet to see confirmations. Publishing successfully is not a
   confirmation that the transaction has been included in a block.

Add `--floonet` before subcommands consistently for test-network wallets/nodes.
Use each CLI's help and the wallet's
[setup guide](https://github.com/mwcproject/mwc-wallet/blob/master/doc/setup.md)
for the exact configuration of that checkout.
