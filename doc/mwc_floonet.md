This page will be a guide for running MWC's floonet. We have launched a testnet, known as the floonet (similar to mwc).
We have two seed servers running at seed1.mwc.mw and seed2.mwc.mw. If you are interested in running a public seed server,
please contact us. As of now, mwc will only run with the --floonet option. This will change as we come closer to launching
mainnet. An important thing to note about the floonet is that the reward schedule decreases much faster than mainnet. On
mainnet, there are 2.1 million blocks (4 years) between block reward halvings. On floonet, there are 2880 blocks (2 days)
between block reward halvings. The purpose of this it to test that our reward halving schedule works correctly. The downside
is that there will be no rewards after about 64 days or so when the final halving occurs. The floonet will still work, but
at that time, we might start a new testnet.

# Setting up a full node
To setup a full node, you must checkout and build the project or you can just download our binaries from our latest release which are hosted here: http://www.github.com/cgilliard/mwc/releases.

## Supported Platforms

Longer term, most platforms will likely be supported to some extent.
MWC's programming language `rust` has build targets for most platforms.

What's working so far?

* Linux x86\_64 and macOS [MWC + mining + development]
* Not Windows 10 yet

## Requirements (only needed to build if you are downloading binaries you can skip this section)

* rust 1.31+ (use [rustup]((https://www.rustup.rs/))- i.e. `curl https://sh.rustup.rs -sSf | sh; source $HOME/.cargo/env`)
  * if rust is already installed, you can simply update version with `rustup update`
* clang
* ncurses and libs (ncurses, ncursesw5)
* zlib libs (zlib1g-dev or zlib-devel)
* pkg-config
* libssl-dev
* linux-headers (reported needed on Alpine linux)
* llvm

For Debian-based distributions (Debian, Ubuntu, Mint, etc), all in one line (except Rust):

```sh
apt install build-essential cmake git libgit2-dev clang libncurses5-dev libncursesw5-dev zlib1g-dev pkg-config libssl-dev llvm
```

There are similar packages available for centos as well but they might have a slightly different name.

For Mac (Only necessary if you plan to build, if you are downloading binaries skip):

```sh
xcode-select --install
brew install pkg-config
brew install openssl
```

## Build steps (If you are downloading binary, skip this step)

```sh
git clone https://github.com/cgilliard/mwc.git
cd mwc
cargo build --release
```

MWC can also be built in debug mode (without the `--release` flag, but using the `--debug` or the `--verbose` flag) but this will render fast sync prohibitively slow due to the large overhead of cryptographic operations.

A successful build gets you:

* `target/release/mwc` - the main mwc binary

If you have downloaded binary, the package will contain the mwc binary only for your specfic platform.

All data, configuration and log files created and used by mwc are located in the hidden
`~/.mwc` directory (under your user home directory) by default. You can modify all configuration
values by editing the file `~/.mwc/main/mwc-server.toml`.

It is also possible to have mwc create its data files in the current directory. To do this, run

```sh
mwc --floonet server config
```
Which will generate a `mwc-server.toml` file in the current directory, pre-configured to use
the current directory for all of its data. Running mwc from a directory that contains a
`mwc-server.toml` file will use the values in that file instead of the default
`~/.mwc/floo/mwc-server.toml`.

While testing, put the mwc binary on your path like this:

```sh
export PATH=`pwd`/target/release:$PATH
```

assuming you are running from the root directory of your MWC installation.

You can then run `mwc` directly (try `mwc help` for more options).

Now that your full node is installed, you can start it on the floonet by running the following command:

```sh
mwc --floonet
```

This will start your full node and you will automatically connect to our seed servers. You can see the mwc-server.toml file
for details on how to configure with different seed servers.

# Running a wallet

To initialize your wallet run the following commands:

```sh
# mkdir mywallet
# cd mywallet
# mwc --floonet wallet init -h
```

Because your wallet is running in a different directory from your floo node, you will need to copy the .api_secret file from the floo directory to your wallet's directory so that it can connect to your node. If you do not do this, you might see a message warning that your wallet was not able to verify data against the live chain.

```sh
# cp ~/.mwc/floo/.api_secret .
```

This will initialize your wallet in the local directory. Whenever you run this wallet you must execute it from that directory.

To check balance, run the following command:

```sh
# mwc --floonet wallet info
```

If you join the floonet, let us know and we will send you coins to test with.

To send coins, run the following command:

```sh
# mwc --floonet wallet send -m file -d tx.tx <amount>
```
This will generate an output file called tx.tx. Transfer this file to the receipient who will run the following command with
tx.tx in the present working directory.

```sh
# mwc --floonet wallet receive -i tx.tx
```
This command will genearte an output file called tx.tx.response. The sender will then finalize the transaction by running the
following command:

```sh
# mwc --floonet wallet finalize -i tx.tx.response
```

You can then confirm balances with the info command.

```sh
# mwc --floonet wallet info
```

# Web wallet

Mwc web wallet is compatible with MWC. You can check how set it up [here](https://github.com/cgilliard/mwc/blob/master/doc/web-wallet.md).

# Mining

To mine mwc, you will need to download and build the mwc miner. It is 100% compatible with mwc. The repository is here:
http://www.github.com/mimblewimble/mwc-miner. Check out the project and build following the instructions in the repository.

To allow mining you must first enable mining on your full node by editing the following line in your mwc-server.toml file:

enable_stratum_server = false

Change it to:

enable_stratum_server = true

You must also start a wallet listener with the following command:

```sh
mwc --floonet wallet listen
```

Now you will be able to mine by starting your mwc miner with the mwc-miner binary that you have built. Note that by default mwc miner will try to connect on port 3416. For the floonet, you will need to change that parameter to 13416. The line in mwc-miner.toml will look like this:

stratum_server_addr = "127.0.0.1:13416"

