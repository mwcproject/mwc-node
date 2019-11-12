# Mining Setup, MAC OS

## About

This document describe how to setup and **verify** MWC node, wallet and be ready for the mining.

## MWC QT Wallet

Please note, mwc-qt-wallet avalailable at [Wallet Download](https://www.mwc.mw/downloads) page is **not for the mining**.
If you are running qt wallet or mwc713, please **stop it and don't use it** during the setup and verification.

## Preperquisited

Please install homebrew at your mac. [https://brew.sh/]

Install 'tree', 'curl' and 'telnet' to validate the setup
```
> brew install tree
> brew install curl
> brew install telnet
```

## High level Architecture

Please check the high level connection diagram and please understand the ports that are used by default. For P2P connection it is enough to have outbound connection. 

For Stratum protocol inbound connection does required.

![](Install_mac_images/architecture.png)

Please note IPs `127.0.0.1` are open for local host connections. `0.0.0.0` are open for all world.

Please Ajust IPs according your needs and update your firewall rules.

Note: By default connections are not entrypted. If you need SSL connections please check how you can setup certificates. It is different topic and not covered in this document.  
   
   

## Data Location, data clean up

mwc-node and mwc-wallet data located at `~/.mwc` directory.

mwc-wallet data located at `~/.mwc/main/wallet_data/`. The most important is a wallet seed  `~/.mwc/main/wallet_data/wallet.seed`

In case you want to do clean setup, you can delete all directory. Please note, you will **lost your wallet** in this case.  
```
rm -rf ~/mwc
``` 

You might need to do a clean up if you mess up with your setup and want to start from the beginning.


## Install of MWC node and mwc-wallet

In this install I am installing everythign at the directory `~/my_mwc_install`. All commands are referred to this path.

Download mwc node from [https://github.com/mwcproject/mwc-node/releases/latest]. We are assuming that your browser put resulting file will be located at `~/Downloads/mwc-node-XXXXX-macos.tar.gz`

Download mwc-wallet from [https://github.com/mwcproject/mwc-wallet/releases/latest]. We are assuming that resulting file will be located at `~/Downloads/mwc-wallet-2.4.5-macos.tar.gz`

Now let's install everything into `~/my_mwc_install`

```bash
mkdir ~/my_mwc_install
cd ~/my_mwc_install
tar -xvf ~/Downloads/mwc-node-*-macos.tar.gz
tar -xvf ~/Downloads/mwc-wallet-*-macos.tar.gz
```

Your output should see something like this:
```
kbay$ mkdir ~/my_mwc_install
kbay$ cd ~/my_mwc_install
my_mwc_install kbay$ tar -xvf ~/Downloads/mwc-node-*-macos.tar.gz
x mwc/
x mwc/mwc
my_mwc_install kbay$ tar -xvf ~/Downloads/mwc-wallet-*-macos.tar.gz
x mwc-wallet/
x mwc-wallet/mwc-wallet
```

Now your mwc node is located at `~/my_mwc_install/mwc/mwc` and your mwc-wallet is located at `~/my_mwc_install/mwc-wallet/mwc-wallet`

## Start the node

Start the node for the first run.
```
kbay$ ~/my_mwc_install/mwc/mwc
```

![](Install_mac_images/scr_node.png)


mwc node has few commands. Run `~/my_mwc_install/mwc/mwc help` to explore them.

Please keep your node running until we setup the wallet. You should be able to see that the node was able connect to the peers and download the chain.


#### Validate the node install

Please check that the node was able to create the files and download the data.

Check the files.
```
kbay$ tree ~/.mwc
/Users/kbay/.mwc
└── main
    ├── chain_data
    │   ├── header
    │   │   ├── header_head
    │   │   │   ├── pmmr_data.bin
    │   │   │   └── pmmr_hash.bin
    │   │   └── sync_head
    │   │       ├── pmmr_data.bin
    │   │       └── pmmr_hash.bin
    │   ├── lmdb
    │   │   ├── data.mdb
    │   │   └── lock.mdb
    │   ├── mwc.lock
    │   ├── peer
    │   │   ├── data.mdb
    │   │   └── lock.mdb
    │   └── txhashset
    │       ├── kernel
    │       │   ├── pmmr_data.bin
    │       │   ├── pmmr_hash.bin
    │       │   └── pmmr_size.bin
    │       ├── output
    │       │   ├── pmmr_data.bin
    │       │   ├── pmmr_hash.bin
    │       │   └── pmmr_leaf.bin
    │       └── rangeproof
    │           ├── pmmr_data.bin
    │           ├── pmmr_hash.bin
    │           └── pmmr_leaf.bin
    ├── mwc-server.log
    └── mwc-server.toml
``` 

Please note the location of the:

logs : `/Users/kbay/.mwc/mwc-server.log`  
config: `/Users/kbay/.mwc/mwc-server.toml`

Meanwhile be free to check the logs at `/Users/kbay/.mwc/mwc-server.log`

If everything goes well, you shouldn't see the ERROR message. Output from that command should be empty
```
>  cat ~/.mwc/main/mwc-server.log | grep 'ERROR'
``` 

**Note: Expected that it is one instance of of the node and wallet are running at the same host!**  
If you try to run several instances, you will likely to see some errors.  

You should wait some time until node will be able to download the blockchain data. In that case UI shows the `Current Status: Running`.
If you see this status, congratulations, your node is running. We can start with a wallet setup.


## Init wallet

If you don't have any mwc wallet, you need to create a new one. Please note, if your already have mwc wallet, you can restore it by the mnemonic. It is covered below.
 
Let's explore first what mwc-wallet can by running:

```
kbay$ ~/my_mwc_install/mwc-wallet/mwc-wallet --help
mwc-wallet 2.4.5
The Grin Team
Reference MWC Wallet

USAGE:
    mwc-wallet [FLAGS] [OPTIONS] [SUBCOMMAND]

FLAGS:
    -e, --external      Listen on 0.0.0.0 interface to allow external connections (default is 127.0.0.1)
        --floonet       Run mwc against the Floonet (as opposed to mainnet)
    -h, --help          Prints help information
    -s, --show_spent    Show spent outputs on wallet output commands
        --usernet       Run mwc as a local-only network. Doesn't block peer connections but will not connect to any peer
                        or seed
    -V, --version       Prints version information

OPTIONS:
    -a, --account <account>                          Wallet account to use for this operation [default: default]
    -r, --api_server_address <api_server_address>
            Api address of running node on which to check inputs and post transactions

    -d, --data_dir <data_dir>                        Directory in which to store wallet files
    -p, --pass <pass>                                Wallet passphrase used to encrypt wallet seed

SUBCOMMANDS:
    account      List wallet accounts or create a new account
    cancel       Cancels an previously created transaction, freeing previously locked outputs for use again
    check        Checks a wallet's outputs against a live node, repairing and restoring missing outputs if required
    finalize     Processes a receiver's transaction file to finalize a transfer.
    help         Prints this message or the help of the given subcommand(s)
    info         Basic wallet contents summary
    init         Initialize a new wallet seed file and database
    invoice      Initialize an invoice transction.
    listen       Runs the wallet in listening mode waiting for transactions
    outputs      Raw wallet output info (list of outputs)
    owner_api    Runs the wallet's local web API
    pay          Spend coins to pay the provided invoice transaction
    receive      Processes a transaction file to accept a transfer from a sender
    recover      Recover a wallet.seed file from a recovery phrase (default) or displays a recovery phrase for an
                 existing seed file
    repost       Reposts a stored, completed but unconfirmed transaction to the chain, or dumps it to a file
    restore      Restores a wallet contents from a seed file
    send         Builds a transaction to send coins and sends to the specified listener directly
    submit       Submits a transaction that has already been finalized but not submitted to the network yet
    txs          Display transaction information
```
Any command can be explored by running `help <command>`. For example this command will show you details for 'init':  `~/my_mwc_install/mwc-wallet/mwc-wallet help init`


To create the new wallet please run command below. We strongly recommend to setup the password for your seed. 
```
kbay$ ~/my_mwc_install/mwc-wallet/mwc-wallet init
Please enter a password for your new wallet
Password:
Confirm Password:
20191111 18:13:13.180 WARN grin_wallet_impls::seed - Generating wallet seed file at: /Users/kbay/.mwc/main/wallet_data/wallet.seed
Your recovery phrase is:

cousin cargo avoid sk ....  fee surround valve prepare

Please back-up these words in a non-digital format.
Command 'init' completed successfully
```
    
Please story recovery phrase in the secure place. That mnemonic will allow you to recovery your funds in a new wallet.

If you already has a wallet, you can init it with your existing seed and that resync it with a node. Please note, if your wallet has any coins, you will see them after resync only.
```
kbay$ ~/my_mwc_install/mwc-wallet/mwc-wallet init -r
Please enter your recovery phrase:
phrase> cousin cargo avoid skull divide goose rather client small disease glass what unfold save ramp donor want either smooth broken coffee surround valve prepare
Please provide a new password for the recovered wallet
Password:
Confirm Password:
20191111 18:17:49.394 WARN grin_wallet_impls::seed - Generating wallet seed file at: /Users/kbay/.mwc/main/wallet_data/wallet.seed
Your recovery phrase is:

cousin cargo avoid sk .... fee surround valve prepare

Please back-up these words in a non-digital format.
Command 'init' completed successfully

kbay$ ~/my_mwc_install/mwc-wallet/mwc-wallet check
Password:
20191111 18:22:25.359 WARN grin_wallet_controller::command - Starting wallet check...
20191111 18:22:25.359 WARN grin_wallet_controller::command - Updating all wallet outputs, please wait ...
20191111 18:22:25.394 WARN grin_wallet_libwallet::internal::restore - Starting wallet check.
20191111 18:22:25.665 WARN grin_wallet_libwallet::internal::restore - Checking 895 outputs, up to index 895. (Highest index: 895)
20191111 18:22:25.666 WARN grin_wallet_libwallet::internal::restore - Scanning 895 outputs in the current MWC utxo set
20191111 18:22:25.739 WARN grin_wallet_libwallet::internal::restore - Identified 0 wallet_outputs as belonging to this wallet
20191111 18:22:25.739 WARN grin_wallet_controller::command - Wallet check complete
Command 'check' completed successfully
``` 

#### Validation

Please validate that your wallet created the files:

```
kbay$ tree ~/.mwc
/Users/kbay/.mwc
└── main
    ├── mwc-wallet.log
    ├── mwc-wallet.toml
    └── wallet_data
        ├── db
        │   └── lmdb
        │       ├── data.mdb
        │       └── lock.mdb
        ├── saved_txs
        └── wallet.seed
```    

Please note the location of the:

logs : `/Users/kbay/.mwc/mwc-wallet.log`  
config: `/Users/kbay/.mwc/mwc-wallet.toml`

Check if there was no Errors during wallet initialization:

```
>  cat ~/.mwc/main/mwc-wallet.log | grep 'ERROR'
```

## Start Listener for the Wallet

In order to do mining mwc-wallet need to run in listening mode. It is needed to create the transactions in case your miner will found the block.

```
kbay$ ~/my_mwc_install/mwc-wallet/mwc-wallet listen
Password:
20191111 18:59:15.332 WARN grin_wallet_controller::controller - Starting HTTP Foreign listener API server at 127.0.0.1:3415.
20191111 18:59:15.333 WARN grin_wallet_controller::controller - HTTP Foreign listener started.
```
And your wallet will run until you will not interrupt it.

Congratulations, if you pass validation, your wallet is ready. Please keep it running until you mining.

#### Validate

Please periodically check if logs don't have errors with:
```
> cat ~/.mwc/main/mwc-wallet.log | grep 'ERROR'
```

Check if Foreign listener API runs well with the command:
```
kbay$  curl -d '{"jsonrpc": "2.0", "method": "build_coinbase", "id": 1, "params": { "block_fees": 7000000}}' http://localhost:3415/v2/foreign
{
  "error": {
    "code": -32602,
    "message": "InvalidArgStructure \"block_fees\" at position 0."
  },
  "id": 1,
  "jsonrpc": "2.0"
}
```

## Setup mwc-node to run miner locally

Please update config for your mwc-node.

- Stop mwc-node if it is running. Please let mwc-wallet ruuning in listening mode.
- Edit `~/.mwc/mwc-server.toml` with your favorite editor.

Change value for `enable_stratum_server` to 
```
#whether stratum server is enabled
enable_stratum_server = true
``` 
- Start mwc-node
```
kbay$ ~/my_mwc_install/mwc/mwc
``` 

You are ready to to run your miner locally at the same host.

#### Validate

Check if there any errors at the node logs
```
>  cat ~/.mwc/main/mwc-server.log | grep 'ERROR'
```

Check if stratum is activated. There are must be a line into the logs:
```
> cat ~/.mwc/main/mwc-server.log | grep 'Stratum server started'
20191111 19:32:36.088 WARN grin_servers::mining::stratumserver - Stratum server started on 127.0.0.1:3416
```

Verify if stratum really works with telnet:
```
kbay$ telnet  127.0.0.1 3416
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
{"id":"Stratum","jsonrpc":"2.0","method":"job","params":{"difficulty":1,"height":966,"job_id":1,"pre_pow":"000100000000000003c6000000005dca285900001d1246f8704600e3ff43c46eb36ff54493004b517ce12a4a22009e74336feac7d18ccd2b1b6a3b84381f9d7e65ad9d83ab7d9f6844a1761d301e4fa30d4af0bfbf06792019ed7e234b0a8a7528d4c46d8f130a9055c0055fc1e3ab51215f6a6cf5035c865ec1320221fdace2a63ed83db57eebea06a195a5ebfb1b06713028a1bf87cc76007cec679dc7cc6650610a16c00c326ed16be15e3d47dbf311880000000000000000000000000000000000000000000000000000000000000000000000000000078700000000000007870000000bbb860467000001a0"}}
^C
Connection closed by foreign host.
```


## Setup mwc-node to run miner on different host at Internet

Please update config for your mwc-node.

- Stop mwc-node if it is running. Please let mwc-wallet ruuning in listening mode.
- Edit `~/.mwc/mwc-server.toml` with your favorite editor.

Change value for `enable_stratum_server` and `stratum_server_addr` 
```
#whether stratum server is enabled
enable_stratum_server = true

#what port and address for the stratum server to listen on
stratum_server_addr = "0.0.0.0:3416"
``` 
stratum_server_addr need listen on 0.0.0.0 in order to accept connections from other hosts.

- Start mwc-node
```
kbay$ ~/my_mwc_install/mwc/mwc
``` 

#### Validate node from local host

Check if there any errors at the node logs
```
>  cat ~/.mwc/main/mwc-server.log | grep 'ERROR'
```

Check if stratum is activated. There are must be a line into the logs:
```
> cat ~/.mwc/main/mwc-server.log | grep 'Stratum server started'
20191111 19:32:36.088 WARN grin_servers::mining::stratumserver - Stratum server started on 127.0.0.1:3416
```

Verify if stratum really works with telnet:
```
kbay$ telnet  127.0.0.1 3416
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
{"id":"Stratum","jsonrpc":"2.0","method":"job","params":{"difficulty":1,"height":966,"job_id":1,"pre_pow":"000100000000000003c6000000005dca285900001d1246f8704600e3ff43c46eb36ff54493004b517ce12a4a22009e74336feac7d18ccd2b1b6a3b84381f9d7e65ad9d83ab7d9f6844a1761d301e4fa30d4af0bfbf06792019ed7e234b0a8a7528d4c46d8f130a9055c0055fc1e3ab51215f6a6cf5035c865ec1320221fdace2a63ed83db57eebea06a195a5ebfb1b06713028a1bf87cc76007cec679dc7cc6650610a16c00c326ed16be15e3d47dbf311880000000000000000000000000000000000000000000000000000000000000000000000000000078700000000000007870000000bbb860467000001a0"}}
^C
Connection closed by foreign host.
```

#### Obtain my public IP.

Your miner will need to initiate connection to your public IP. You can get your Public IP from here  [https://whatismypublicip.com/]

Please store your IP, you will need it to setup your miner and validate the setup.

#### Open port at Mac OS

Please do search by your self how to open port MAC OS firewall. 
The easiest way is to disable the firewall.

#### Do you have a router? Map 3416 port for income connections

If you have a router you need to setup the port forwarding for income connections.

If you don't know how to do that, please do the search for the phrase: how to setup 'router brand' port forwarding.   
For example: `how to setup Negtgear port forwarding`  will return you a link  
[https://www.noip.com/support/knowledgebase/setting-port-forwarding-netgear-router-genie-firmware/]

We recommend you just map your router port 3416 to your device local IP address.  

Here is how you can find your local IP for mac [http://osxdaily.com/2010/11/21/find-ip-address-mac/]

#### Validate if your port is open for INCOME connections

Please verify that Port Tester shows that your port is open:
[https://www.yougetsignal.com/tools/open-ports/]

Here is how looks like when I didn't open port at my router, didn't disable firewall, or didn't run mwc-node with a proper setup.

![](Install_mac_images/port_close.png)

Here how it si looks like when I did everything properly.

![](Install_mac_images/port_open.png)

**Please note! It doesn't make sense continue with miner if your port is not open!** This tool works well and if your port is closed it is mean that 
 router, firewall or mwc-node are not configured well. 
 
#### Validate stratum connection from your miner side

If you can ssh to the miner host, please validate with telnet is miner can access the node:
```
kbay$ telnet  <MWC_NODE_PUBLIC_IP> 3416
Trying 24.4.197.142...
Connected to localhost.
Escape character is '^]'.
{"id":"Stratum","jsonrpc":"2.0","method":"job","params":{"difficulty":1,"height":966,"job_id":1,"pre_pow":"000100000000000003c6000000005dca285900001d1246f8704600e3ff43c46eb36ff54493004b517ce12a4a22009e74336feac7d18ccd2b1b6a3b84381f9d7e65ad9d83ab7d9f6844a1761d301e4fa30d4af0bfbf06792019ed7e234b0a8a7528d4c46d8f130a9055c0055fc1e3ab51215f6a6cf5035c865ec1320221fdace2a63ed83db57eebea06a195a5ebfb1b06713028a1bf87cc76007cec679dc7cc6650610a16c00c326ed16be15e3d47dbf311880000000000000000000000000000000000000000000000000000000000000000000000000000078700000000000007870000000bbb860467000001a0"}}
^C
Connection closed by foreign host.
```
  
#### Node setup is DONE for access from the internet.

Congratulations, if you pass all validation steps, you are done with setup for mwc-node and mwc node. 
You can finish miner setup.


## MINER

There are many miner that you can run. MWC miner 100% compartible with grin miner. If you are mining for grin, just redirect to mwc node.

#### Grin miner

MWC clone of grin miner you can get here [https://github.com/mwcproject/grin-miner]
Please follow the instruction how to set it up.

#### GMiner

If you are rinning GMiner please run.
User name can have any value. You will see your miner at the mwc-node under this name.

Your server IP should be 127.0.0.1 if you run your miner on the same host where you run mwc node and mwc-wallet.
Or you should use your mwc node public IP if it is run on different host. Please check that your port is open and 'Validate stratum connection from your miner side' is passed.

It is how you can run for C31
```
miner.exe --algo grin31 --server <NODE_IP>  --port 3416 --user WhatEverName
```
OR for C29d
```
miner.exe --algo cuckarood29 --server <NODE_IP> --port 3416 --user WhatEverName
```


