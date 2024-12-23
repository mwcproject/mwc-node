# Mwc - 构建，配置和运行

*阅读其它语言版本: [English](../build.md), [Español](build_ES.md), [日本語](build_JP.md), [Korean](build_KR.md).*

## 支持的平台

从长远来看，大多数平台都可能会得到一定程度的支持。Mwc 的编写语言 `rust` 已为大多数平台建立了目标。

到目前为止进度：

* Linux x86\_64 and macOS [mwc + 挖矿 + 部署]
* 暂时不支持 Windows 10 [部分 mwc。暂时不支持挖矿。希望得到帮助！]

## 要求

* rust 1.34+ (使用 [rustup]((https://www.rustup.rs/))- i.e. `curl https://sh.rustup.rs -sSf | sh; source $HOME/.cargo/env`)
* 如果已经安装过了 rust，只需要运行 `rustup update` 升级版本
* clang
* ncurses 和 libs (ncurses, ncursesw5)
* zlib libs (zlib1g-dev or zlib-devel)
* pkg-config
* libssl-dev
* linux-headers (有报告指出在 Alpine linux 上是必需的)
* llvm

对于基于 Debian 的发行版（Debian，Ubuntu，Mint 等），一行就可以搞定（rust 的安装除外）：

```sh
apt install build-essential cmake git libgit2-dev clang libncurses5-dev libncursesw5-dev zlib1g-dev pkg-config libssl-dev llvm
```

macOS 用户:

```sh
xcode-select --install
brew install --with-toolchain llvm
brew install pkg-config
brew install openssl
```

## 构建步骤

```sh
git clone https://github.com/mwcproject/mwc-node.git
cd mwc-node
cargo build --release
```

Mwc也可以在 debug 模式下构建（不带 `--release` 参数，或是使用 `--debug` 或 `--verbose` 参数），但是由于加密的开销很大，这将影响快速同步的性能。

## 构建错误

详见 [故障排除](https://github.com/mimblewimble/docs/wiki/Troubleshooting)

## 构建得到了什么？

成功的构建可以提供给您：

* `target/release/mwc` - mwc 主要的二进制文件

默认情况下，mwc 创建和使用的所有数据，配置和日志文件都位于隐藏的 `~/.mwc` 目录中（位于用户主目录下）。
您可以通过编辑文件 `~/.mwc/main/mwc-server.toml` 来修改所有配置。

也可以让 mwc 在当前目录中创建其数据文件。只需要运行

```sh
mwc server config
```

它将在当前目录中生成一个 `mwc-server.toml` 文件，该文件已预先配置为使用当前目录中的所有数据。
在包含 `mwc-server.toml` 文件所在的目录下运行 mwc 将使用该文件中的配置，而不是默认的 `~/.mwc/main/mwc-server.toml`。

在测试时，将 mwc 二进制文件放在您的 `PATH` 中，如下所示：

```sh
export PATH=`pwd`/target/release:$PATH
```

假设您从 Mwc 安装的根目录运行。

然后您可以直接运行 `mwc`（尝试使用 `mwc help` 获得更多选项）。

## 配置

Mwc 尝试使用合理的默认值运行，并且可以通过 `mwc-server.toml` 文件进行进一步配置。
该文件是在首次运行时由 mwc 生成的，并且包含有关每个可用选项的文档。

虽然建议您通过 `mwc-server.toml` 配置 mwc 服务器，但也可以提供命令行开关以覆盖文件中的任何设置。

有关 mwc 命令及其开关的帮助，请尝试：

```sh
mwc help
mwc wallet --help
mwc client --help
```

## Docker

```sh
docker build -t mwc -f etc/Dockerfile .
```
对于 floonet, 使用 `etc/Dockerfile.floonet` 代替

您可以绑定安装您的 mwc 缓存以在容器中运行。

```sh
docker run -it -d -v $HOME/.mwc:/root/.mwc mwc
```
如果您更喜欢使用名为 volume 的 docker，则可以传递 `-v dotmwc: /root/.mwc` 以替换。
使用命名卷在创建卷时会复制默认配置。

## 跨平台构建

Rust（cargo）可以在许多平台上构建 mwc，因此从理论上讲，可以在低功耗设备上运行 `mwc` 作为验证节点。要在 x86 Linux 平台上交叉编译 `mwc` 并生成 ARM 二进制文件，例如，为一个 Raspberry Pi。

## 使用 mwc

Wiki页面 [Wallet User Guide](https://github.com/mimblewimble/docs/wiki/Wallet-User-Guide) 和链接页面提供了有关我们提供的功能，故障排除等更多信息。

## 在 Mwc 中挖矿

请注意，针对 Mwc 的所有挖矿功能已移至一个名为 [mwc-miner](https://github.com/mwcproject/mwc-node-miner) 的独立软件包中。
一旦您的 Mwc 代码节点启动并运行，就可以通过针对正在运行的 Mwc 节点构建并运行 mwc-miner 开始挖矿。

为了使 mwc-miner 能够与您的 mwc 节点进行通信，请确保在您的 `mwc-server.toml` 配置文件中有 `enable_stratum_server = true`，并且您正在运行钱包监听器（`mwc wallet listen`）。
