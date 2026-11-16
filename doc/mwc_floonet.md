# Floonet node and wallet setup

Floonet is MWC's public test network for testing node, wallet and application
changes with test coins. Use `--floonet` for both the node and wallet commands.
The examples below use one node and a separate wallet directory on the same
host.

The built-in Floonet seed list includes `seed1.mwc.mw`, `seed2.mwc.mw`, IP
addresses and Tor peers. The node uses these to discover peers automatically.
See [the seed list](../core/src/global.rs) and the generated configuration for
peer settings. To offer a public seed, keep a synchronized node reachable on
its P2P port and coordinate inclusion with the project maintainers.

Floonet accelerates the early reward transitions to exercise the reward
schedule. The current subsidy changes are defined by block height:

| First block of the period | Subsidy per block |
| --- | --- |
| 1 | 2.380952380 MWC |
| 271,440 | 0.6 MWC |
| 272,880 | 0.45 MWC |
| 274,320 | 0.3 MWC |

The 0.6 and 0.45 MWC periods each last 1,440 blocks on Floonet; on mainnet they
last 120 and 60 days' worth of blocks. Later periods have longer durations.
Use `calc_mwc_block_reward`, `get_epoch_block_offset` and `get_epoch_duration`
in [the consensus implementation](../core/src/consensus.rs) for the complete
schedule. A mined block's reward includes its subsidy plus transaction fees;
fees remain available after the subsidy schedule ends.

## Setting up a full node

Use matching node and wallet releases from
[mwc-node releases](https://github.com/mwcproject/mwc-node/releases) and
[mwc-wallet releases](https://github.com/mwcproject/mwc-wallet/releases), or
build compatible source revisions using the steps below.

### Supported Platforms

The node and wallet support Linux, macOS and Windows. Choose binaries matching
your OS and CPU architecture. Mining workers have their own hardware and
platform requirements; select a worker with an MWC C31 solver.

The command examples here use a Linux/macOS shell. For platform installation,
archive checks and runtime libraries, see the [Linux](mining/install_linux.md),
[macOS](mining/Install_mac.md) and [Windows](mining/install_windows.md) guides.
Use the Floonet ports and `--floonet` commands from this page.

### Requirements (building from source)

Install stable Rust using [rustup](https://rustup.rs). Update an existing Rust
installation with:

```sh
# Update the compiler and Cargo used for the source build.
rustup update stable
```

On Debian-based distributions, install the native build tools and libraries:

```sh
# GCC/G++, Make, CMake, pkg-config, and development libraries for the node.
sudo apt update
sudo apt install build-essential cmake git curl pkg-config libncurses-dev zlib1g-dev
```

The standalone node's terminal UI uses curses. On other Linux distributions,
install the corresponding development packages for the same tools and libraries.

On macOS, use Apple Clang and the Homebrew build dependencies:

```sh
# Install Apple's compiler, SDK and command-line tools.
xcode-select --install

# Install CMake, pkg-config and liblzma.
brew install cmake pkg-config xz
```

For Windows source builds, use the MSVC Rust toolchain, Visual Studio's C++
build tools and Windows SDK; see the Windows installation guide above.
[Build and run](build.md) has further node build details.

### Build steps (building from source)

For new source checkouts, keep the node and wallet repositories side by side.
The wallet's local dependency paths refer to the sibling `mwc-node` directory.
For existing checkouts, run the build commands in those directories.

```sh
# Create a directory for the two source repositories.
mkdir -p ~/mwc-dev
cd ~/mwc-dev
git clone https://github.com/mwcproject/mwc-node.git
git clone https://github.com/mwcproject/mwc-wallet.git

# Build the standalone node.
cd ~/mwc-dev/mwc-node
cargo build --release

# Build the standalone wallet.
cd ~/mwc-dev/mwc-wallet
cargo build --release

# Make both executables available in this terminal.
export PATH="$HOME/mwc-dev/mwc-node/target/release:$HOME/mwc-dev/mwc-wallet/target/release:$PATH"
```

Successful builds produce `mwc-node/target/release/mwc` and
`mwc-wallet/target/release/mwc-wallet` (`.exe` on Windows). Use release builds
for synchronization and normal operation; cryptographic validation is much
slower in debug builds.

### Make the executables available

Run the appropriate `PATH` command in each terminal used in this walkthrough.
For source builds, use the export above. For release archives extracted as in
the installation guides:

```sh
# Adapt these directories if you extracted the releases elsewhere.
export PATH="$HOME/my_mwc_install/mwc:$HOME/my_mwc_install/mwc-wallet:$PATH"

# Each command should print the installed program's version.
mwc --version
mwc-wallet --version
```

Check that the versions match the releases or source revisions you selected.
If a command is missing, correct `PATH`. Resolve any loader or library error
using the platform installation guide before proceeding.

### Configure and start the node

By default, Floonet configuration, data and logs live under `~/.mwc/floo`.
For this walkthrough, generate a configuration in a dedicated directory:

```sh
# Keep this node's configuration, chain database and logs together.
mkdir -p ~/mwc-floonet/node
cd ~/mwc-floonet/node

# First run only: create mwc-server.toml with paths rooted in this directory.
mwc --floonet server config

# Start the node and leave this terminal running.
mwc --floonet server run
```

The configuration command reports that it created `mwc-server.toml`.
The node reads that file from its working directory and creates `chain_data`,
its API credential files and `mwc-server.log` there. For later starts, return
to the same directory and run `mwc --floonet server run`.

These are the Floonet ports used throughout this page:

| Service | Address or port |
| --- | --- |
| Node API | `127.0.0.1:13413` |
| P2P | TCP `13414` |
| Wallet foreign API, when enabled below | `127.0.0.1:13415` |
| Node Stratum server, when enabled below | `127.0.0.1:13416` |
| Wallet owner API | `127.0.0.1:13420` |

Wait for `Current Status: Running`, then check that the validated chain height
has caught up with the header chain and connected peers. Keep the node running
while using the wallet. If synchronization stalls, follow
[Chain synchronization](chain/chain_sync.md).

For custom seed peers, edit `[server.p2p_config]` in the generated configuration.
Use `seeding_type = "List"` with `seeds` containing reachable Floonet peers in
`IP:13414` form, then restart the node. The generated comments describe the
available peer options. See [Tor configuration](tor_inbound_feature.md) for
onion peers and [API authentication](api/api.md) for node API access.

## Running a wallet

### Initialize the wallet and connect it to the node

In another terminal, initialize the wallet in its own directory:

```sh
# Create the wallet configuration and data in this directory.
mkdir -p ~/mwc-floonet/wallet
cd ~/mwc-floonet/wallet
mwc-wallet --floonet init --here

# Give the wallet the running node's foreign API credential.
cp ~/mwc-floonet/node/.foreign_api_secret .foreign_api_secret
chmod 600 .foreign_api_secret
```

Follow the password prompts and store the generated recovery phrase securely.
Initialization creates `mwc-wallet.toml` and `wallet_data/wallet.seed`.

The generated `[wallet]` section uses the local Floonet node:

```toml
[wallet]
check_node_api_http_addr = "http://127.0.0.1:13413"
```

Keep its generated absolute `node_api_secret_path`, which points to the
`.foreign_api_secret` file copied into the wallet directory. If the node's
credential changes, copy its updated file again. For a different node, update
the URL and obtain its foreign API credential from its operator.

Run wallet commands from this directory so they load this wallet's configuration:

```sh
# Refresh wallet state from the node and show the balance.
cd ~/mwc-floonet/wallet
mwc-wallet --floonet info
```

Expect a wallet summary with the refreshed block height and `Currently
Spendable` balance. A new wallet starts with zero funds. If the wallet reports
that it could not validate against the node, check that the node is running,
the API address is correct and the copied secret matches.

### Obtain test coins

Use the Floonet faucet to fund the wallet initialized above. Keep your Floonet
node running and synchronized, then run:

```sh
# Request 3 test MWC; the command accepts up to 5 MWC per request.
cd ~/mwc-floonet/wallet
mwc-wallet --floonet faucet_request --amount 3

# Refresh the balance after the transaction reaches the chain.
mwc-wallet --floonet info
```

Enter the wallet password when prompted. `--amount` accepts decimal amounts,
such as `1.2`, up to **5 MWC** per request; omitting it requests **3 MWC**.
The command starts the MWCMQS listener, sends the request to the Floonet
faucet, then finalizes and posts the returned transaction automatically.

Expect `Command 'faucet_request' completed successfully`. The `info` command
refreshes the balance and shows the received funds as awaiting confirmation or
confirmed, depending on chain progress. Run `mwc-wallet --floonet info` again
after new blocks arrive to see the confirmation status update.

The faucet may need a few minutes to synchronize after being idle. If the
request fails, wait a couple of minutes and retry. For an extended outage,
contact a moderator in the `#developers` channel on
[MWC Discord](https://discord.gg/n5dZaty).
The wallet's [Floonet faucet guide](https://github.com/mwcproject/mwc-wallet/blob/master/doc/floonet_faucet.md)
also explains how to return test coins when you have finished testing.

### Send, receive and finalize a transaction

These steps exchange encrypted Slatepack files between two Floonet wallets.
The sender needs sufficient spendable funds for the amount plus the fee.
The CLI's default input confirmation threshold is 10 blocks.

First, the receiver displays its address and gives it to the sender:

```sh
# Receiver: run in the receiving wallet's directory.
cd ~/mwc-floonet/wallet
mwc-wallet --floonet address
```

Use the receiver's Tor/Ed25519 address for Slatepack encryption. On the sender's
machine, replace the address placeholder before running:

```sh
# Sender: create a Slatepack sending 1 test MWC to the receiver.
cd ~/mwc-floonet/wallet
FLOONET_RECIPIENT='REPLACE_WITH_RECEIVER_ADDRESS'
mwc-wallet --floonet send --method slatepack \
  --slatepack_recipient "$FLOONET_RECIPIENT" --dest tx.slatepack 1
```

Expect `tx.slatepack` in the sender's wallet directory. Transfer that file to
the receiver, who places it in their wallet directory and runs:

```sh
# Receiver: sign the incoming Slatepack and save a response file.
cd ~/mwc-floonet/wallet
mwc-wallet --floonet receive --file tx.slatepack --outfile tx.response.slatepack
```

Expect `tx.response.slatepack`. Return it to the sender, who saves it in their
wallet directory and finalizes:

```sh
# Sender: finalize the returned response and broadcast the transaction.
cd ~/mwc-floonet/wallet
mwc-wallet --floonet finalize --file tx.response.slatepack
```

On success, the transaction is posted to the node for inclusion in a block.
After confirmation, both parties refresh their wallets:

```sh
# Sender and receiver: refresh balances and inspect transaction status.
cd ~/mwc-floonet/wallet
mwc-wallet --floonet info
mwc-wallet --floonet txs
```

The receiver's balance should include the received amount; the sender's balance
reflects the payment and fee. `txs` shows the corresponding transaction and
confirmation status. If a step reports an error, resolve it before proceeding
to the next step. For signing with an offline wallet, see
[the offline workflow](offline_wallet.md).

## Web wallet

For a browser wallet integration, use a frontend compatible with the current
`mwc-wallet` owner API. Start the authenticated API backend for this test wallet:

```sh
# Wallet terminal: expose the local owner API for the browser frontend.
cd ~/mwc-floonet/wallet
mwc-wallet --floonet owner_api
```

Expect an owner API startup message for `127.0.0.1:13420`, followed by the
process remaining active. A binding error means another process is using the
port; stop that instance or configure a distinct `owner_api_listen_port`.

Run the frontend separately and configure it to use
`http://127.0.0.1:13420/v3/owner`. Keep `api_secret_path` configured: the generated
`.owner_api_secret` supplies the HTTP Basic authentication password, with
username `mwc`. A v3 client also performs `init_secure_api` and encrypts its
subsequent API requests. See the wallet's
[v3 owner API example](https://github.com/mwcproject/mwc-wallet/tree/master/doc/samples/v3_api_node)
for the handshake and client configuration.

Use the frontend's connection check to confirm it can authenticate, open the
Floonet wallet and retrieve its balance. Stop the owner API with Ctrl+C when
finished with this optional setup.

## Mining

Use an MWC Cuckatoo31 worker compatible with the mining host. Obtain the worker
from [mwc-miner](https://github.com/mwcproject/mwc-miner), or use another worker
supporting MWC C31 and its Stratum protocol. The platform installation guides
linked above cover worker dependencies and plugin selection.

### Enable the wallet's mining listener

In the existing `[wallet]` section of
`~/mwc-floonet/wallet/mwc-wallet.toml`, set these values and retain the other
generated settings:

```toml
[wallet]
api_listen_interface = "127.0.0.1"
api_listen_port = 13415
check_node_api_http_addr = "http://127.0.0.1:13413"
```

Start the socket listener and enter the wallet password:

```sh
# Wallet terminal: keep the listener running while mining.
cd ~/mwc-floonet/wallet
mwc-wallet --floonet listen --no_tor
```

From another terminal, check that the configured socket serves the foreign API:

```sh
# Expect result.Ok with foreign_api_version and supported_slate_versions.
curl -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"check_version","params":[]}' \
  http://127.0.0.1:13415/v2/foreign
```

If the connection fails, check the listener process and its interface/port
settings. For an API error, use its message and `mwc-wallet.log` to identify
the cause. The node uses this listener to create coinbase reward outputs.

### Enable Stratum on the node

Stop the node using its terminal UI's Quit action. Update the existing
`[server.stratum_mining_config]` section in
`~/mwc-floonet/node/mwc-server.toml`:

```toml
[server.stratum_mining_config]
enable_stratum_server = true
stratum_server_addr = "127.0.0.1:13416"
wallet_listener_url = "http://127.0.0.1:13415"
burn_reward = false
```

Restart the node while the wallet listener remains running:

```sh
# Node terminal: load the updated mining configuration.
cd ~/mwc-floonet/node
mwc --floonet server run
```

Expect `Stratum server started on 127.0.0.1:13416` in `mwc-server.log` for this
run. The node serves jobs after synchronization and a successful coinbase
request to the wallet. If mining startup fails, check the node and wallet log
entries for the reported address, connection or coinbase error.

### Configure and run the worker

For the reference `mwc-miner`, update the existing `[mining]` section in
`grin-miner.toml`:

```toml
[mining]
stratum_server_addr = "127.0.0.1:13416"
stratum_server_login = "floonet-worker"
stratum_server_password = "x"
stratum_server_tls_enabled = false
```

Enable a C31 plugin appropriate for your hardware. For a built reference miner
at `~/mwc-miner`, start it from the directory containing its configuration:

```sh
# Worker terminal: use the reference miner's executable and Floonet settings.
cd ~/mwc-miner
./target/release/grin-miner
```

Expect the worker to log in, receive jobs and appear as `floonet-worker` in the
node's Mining screen. Accepted shares indicate valid submitted work. When the
node accepts a mined block, the configured wallet receives its coinbase reward.

```sh
# Refresh rewards and inspect coinbase output status.
cd ~/mwc-floonet/wallet
mwc-wallet --floonet info
mwc-wallet --floonet outputs
```

`info` shows the reward under `Immature Coinbase` until it matures;
`outputs` identifies it through its `Coinbase?`, `Block Height` and `Status`
fields. Floonet coinbase maturity is 1,440 blocks. For a worker on another
host, use the installation guides' remote-worker steps with Floonet Stratum
port `13416`. See [Stratum protocol](stratum.md) for job and submission details.
