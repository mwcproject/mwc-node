# Overview #

Given the nature of MWC, given it's limited supply, it will be important to be able to properly secure coins. Currently in
mwc, there is no way that we are aware of to send funds from an offline wallet. We are not aware of a way to do this in
Beam either. We have implemented new function in the MWC wallet called "submit". It submits a transaction to the network
that has been finalized on an offline node. This will enable both sending and receiving funds with an offline airgapped
wallet. We felt this was a necessity for users to be able to securely store their funds in MWC.

# Lifecycle of an offline, secure wallet #

In order to create an offline MWC wallet, the first step is boot up from a live CD. One option is Ubuntu live cd which can
be found here: https://help.ubuntu.com/community/LiveCD.

You will most likely want to use a USB stick instead of an actual CDROM. You will also need a second USB stick to transfer
files to and from your offline install. Make sure to never enable networking on your LiveCD install to ensure the top level
of security.

First step after installing your new OS is to copy the MWC binary to the USB stick. Plug the USB stick into your offline
computer and copy mwc to the local file system and add it to your path. Run the following command to setup an offline full
node:

```
# mkdir offline_node
# cd offline_node
# mwc server config
```

This will setup a full node in that directory. Next you will need copy the chain_data directory from a fully synced full node
over to your offline node. The chain data can be found in ~/.mwc/main/chain_data/ (or floo directory for floonet) by default
and should be copied into the offline_node/chain_data directory. You will need to use a USB stick to do this.

Next you will need to setup a wallet. Run the following commands:

```
# cd offline_node
# mwc-wallet init -h
```

This will initialize your wallet in the same directory as your offline full node. At this point, you can now receive
transactions via file. See our floonet page on how to do that:
https://github.com/cgilliard/mwc/blob/master/doc/mwc_floonet.md. You will need to transfer the transaction files via USB
stick to and from the offline computer.

Up until this point, all of this was possible in mwc, but the problem arises when you submit the transaction to the network
from an offline node. The last step is the "finalize" command and that both signs the transaction and submits to the network.
The next section will describe a new function we created called the "submit" function which is checked the git repository.

Before you call the submit function, you need to call finalize on your offline node as described on the other wiki page. This
will create a file in your offline_node/wallet_data/saved_txs/ directory copy this transaction file from your offline node
to any online node to "submit" it. The next section explains how the "submit" command works.

# Submit wallet function #

We added a new command to the mwc wallet. Here's the help message for it:

```
# mwc-wallet submit --help
mwc-wallet-submit 
Submits a transaction that has already been finalized but not submitted to the network yet

USAGE:
    mwc wallet submit [FLAGS] [OPTIONS]

FLAGS:
    -f, --fluff      Fluff the transaction (ignore Dandelion relay protocol)
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -i, --input <input>    Transaction file to submit
```

The command should be fairly self explanitory. You copy the transaction file which was created in the last section over to
your online node and run the sumbit command to submit. For example:

```
# mwc-wallet submit -i 856854b4-d9b7-4639-a47a-2edc0f5cf8ab.mwctx
```

This will send this transaction to the network without requiring your offline node to connect to the internet.

# Summary and conclusion #

As we mentioned in the begining since MWC has a limited supply, the secure storage of coins is important. The submit function,
which we implemented will enable offline nodes to send and recieve transactions. This will also likely be enabled in our GUI
based wallet which is under development, as security is a priority.
