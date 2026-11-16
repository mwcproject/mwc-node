# Build and run the node

## Requirements

Install the latest stable Rust using [rustup](https://rustup.rs). If Rust is
already installed, update it with `rustup update`.

The build also needs a native C/C++ toolchain, CMake and pkg-config. The `mwc`
executable includes a Cursive/pancurses terminal UI and needs the corresponding
curses development support on its platform.
The embedded `mwc_node_lib` and Qt wallet library builds do not enable that UI.

For Debian-based distributions (Debian, Ubuntu, Mint):

```sh
sudo apt update
sudo apt install build-essential cmake git curl pkg-config libncurses-dev zlib1g-dev
```

`build-essential` supplies GCC/G++ and Make, matching the Linux build pipeline.
`libncurses-dev` provides the curses development libraries, including wide-character
support, on current Debian and Ubuntu releases.

For macOS, install the Xcode command-line tools and the additional tools through
Homebrew:

```sh
xcode-select --install
brew install cmake pkg-config xz
```

Use Apple Clang from the Xcode command-line tools, as the macOS build pipeline
does. The `xz` package supplies liblzma for compression.

## Build

From the repository root:

```sh
cargo build --release
```

The executable is `target/release/mwc` (`mwc.exe` on Windows). Use a release
build for normal operation: cryptographic validation and initial synchronization
are much slower in a debug build.

For an application embedding the node:

```sh
cargo build --release -p mwc_node_lib --lib
```

This produces an rlib, static library and dynamic library. `mwc_crates/tui` is
optional; the root executable explicitly enables it. Build the embedded target
separately from the executable to avoid feature unification pulling terminal
UI dependencies into that invocation. See [the C ABI](mwc_lib_specification.md).

For macOS applications embedding the node, use the same architecture, SDK
deployment target and Rust linker flags as the embedding application.
The Qt project's [macOS build guide](https://github.com/mwcproject/mwc-qt-wallet/blob/master/DOC/BUILDING_MAC.md)
describes the tested Apple Silicon development setup.

## Configuration and running

Defaults live under `~/.mwc/main` (mainnet) or `~/.mwc/floo` (Floonet).
To generate configuration in a dedicated directory:

```sh
mkdir node-data
cd node-data
/path/to/mwc server config
/path/to/mwc server run
```

For Floonet, use `mwc --floonet server config` and `mwc --floonet server run`.
A `mwc-server.toml` in the working directory takes precedence over the default
location. An explicit configuration is selected with
`mwc server --config_file /path/to/mwc-server.toml run`.
Keep the network selection consistent with that configuration.

```sh
mwc --help
mwc server --help
mwc client --help
```

The CLI provides `server run`, not the old `server start` daemon command.
Generated TOML comments document options; consult [API authentication](api/api.md)
and [Tor configuration](tor_inbound_feature.md) before connecting clients.

## Mining

Mining workers run in the separate `mwc-miner` project. The node still serves
Stratum jobs when `enable_stratum_server = true` in
`[server.stratum_mining_config]`. Its `wallet_listener_url` must point to a
running wallet foreign listener on the matching network. The node executable
does not include wallet subcommands.

## Release packaging

The repository's [release job](../.ci/release.yml) defines archive creation,
checksum generation and artifact uploads. Its conditions and platform jobs
are configured in [azure-pipelines.yml](../azure-pipelines.yml).
