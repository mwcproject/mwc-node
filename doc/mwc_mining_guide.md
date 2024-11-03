# Overview #
This page is intended to be the mining guide for MWC. Since MWC is a fork of [Mwc](https://github.com/mwcproject/mwc-node),
[Mwc Miner](https://github.com/mwcproject/mwc-node-miner) can be used to mine MWC. Mwc miner must be pointed at an
[MWC full node](https://github.com/mwcproject/mwc-node). Mwc supports two mining algorithms: C29 (ASIC resistant) and C31+
(ASIC friendly). MWC supports both of those algorithms as well, but on launch, we will support C29d (a variant of the C29
algorithm). Mwc's mining algorithm allows for 90% of the block rewards to go to C29 miners initially and then gradually go
down to 0% C29 two years after its launch. Since we are launching one year later, we will start at 45% C29d and gradually go
to 0% one year after launch. This is intended to keep us inline with Mwc. Mwc launched with the intent of doing a hard fork
every 6 months. We want to avoid doing that so we are likely to keep the C29d algorithm for the duration of the year that C29
is supported. We do reserve the right to do a hard fork should asics become a problem, but 6 months after launch C29 will only
account for less than 25% of the network so we hope to avoid hard forks all together.

# Procedure to mine #

1.) Setup and install a mwc miner: [Mwc Miner](https://github.com/mwcproject/mwc-node-miner). You will need a GPU that has
at least 5.5 GB of VRAM to effectively mine on the network. There are many discussions about which miners are best for Mwc
and they all apply equally to MWC since we use the same mining algorithm. Nvidia RTX 2070 Ti is a good GPU for mining C29d
and Nvidia RTX 2080 Ti is a good GPU for mining C31+, but there are many other options and C31 ASICs are on the horizon.

2.) Setup an MWC full node and wallet: [MWC full node](https://github.com/mwcproject/mwc-node) and
[mwc-wallet](https://github.com/mwcproject/mwc-wallet).

3.) Modify your mwc-node's mwc-server.toml file to enable stratum server (by default this file is in
~/.mwc/main/mwc-server.toml:
change:
enable_stratum_server = false
to:
enable_stratum_server = true
and restart the mwc-node.

4.) Start your mwc-wallet listener:

```# mwc-wallet listen --no_tor```

5.) Modify your mwc-miner.toml to point to your mwc-node:
stratum_server_addr = "127.0.0.1:3416" (that is the default port of the stratum server in the mwc-node)

6.) start mining:

```# mwc-miner```

Note: you must be using either one of the C31 plugins.

You are done and the block rewards will go to the mwc-wallet instance that you setup. 

Please check mwc-node and mwc-miner logs for errors. Wallet related errors you should see in mwc-node logs. 

if node not able connect to the wallet, use can trouble shout but running this API manually  
```
curl -d '{"id":1,"jsonrpc":"2.0","method":"build_coinbase","params":{"block_fees":{"fees":"0","height":"1307101","key_id":"030000000000000000000c02fd00000000"}}}' http://localhost:3415/v2/foreign
```

# Reward Schedule #

MWC has a different reward schedule from mwc. Mwc's block reward subsidy is 60 mwcs per block indefinitely. MWC's
block reward subsidy starts at 2.380952380 MWC per block and has a halving every 4 years. After 32 halvings, the reward
subsidy is 0 MWC.
