# Mining Setup, Windows 10

## About

This document describes how to setup and **verify** the MWC full node, wallet and be ready for mining.

## MWC QT Wallet

Please note, the mwc-qt-wallet available at the [Wallet Download](https://www.mwc.mw/downloads) page is **not for mining**.
If you are running qt wallet or mwc713, please **do not try to use it for mining**.

## Preperquisited

Init Telnet if you don't have yet [https://www.technipages.com/windows-10-enable-telnet]

Expected that you have a PowerShell. All commands will be run from Windows 10 PowerShell.

## High level Architecture

Please check the high level connection diagram and understand the ports that are used by default. For P2P connections it is enough to have outbound connections. For Stratum protocol inbound connection are required.

![](Install_mac_images/architecture.png)

Please note IPs `127.0.0.1` are open for only local host connections. `0.0.0.0` allows anyone to connect to your host.

Please adjust IPs according to your needs and update your firewall rules.

Note: By default connections are not entrypted. If you need SSL connections you will need to configure certificates as well. It is a different topic and is not covered in this document.

## Data Location, data clean up

mwc-node and mwc-wallet data is located in the `~/.mwc` directory.

mwc-wallet data is located in the `~/.mwc/main/wallet_data/` directory. The most critical piece of data is the wallet seed found at `~/.mwc/main/wallet_data/wallet.seed`.

In case you want to do clean setup, you can delete all directories. Please note, you will **lose any funds in your wallet** in this case.
```
rm -rf ~/.mwc
```

You might need to do this to clean your setup if an error is made.

## Install of MWC node and mwc-wallet

In this install we will install everything at `~/my_mwc_install`. All commands referred to assume this path.

Download mwc node from [https://github.com/mwcproject/mwc-node/releases/latest]. We are assuming that the resulting file will be located at `~/Downloads/mwc-node-XXXXX-win-x64.zip`.

Download mwc-wallet from [https://github.com/mwcproject/mwc-wallet/releases/latest]. We are assuming that the resulting file will be located at `~/Downloads/mwc-wallet-XXXXX-win-x64.zip`.

Now let's install everything into `~/my_mwc_install`.

```bash
mkdir ~/my_mwc_install
cd ~/my_mwc_install
expand-archive -path ~/Downloads/mwc-node-*-win-x64.zip -destinationpath .
expand-archive -path ~/Downloads/mwc-wallet-*-win-x64.zip -destinationpath .
```

Your output should be something like this:
```
PS C:\Users\konst> mkdir ~/my_mwc_install                                                                            

    Directory: C:\Users\konst


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       11/11/2019  10:03 PM                my_mwc_install


PS C:\Users\konst> cd ~/my_mwc_install      
PS C:\Users\konst\my_mwc_install> expand-archive -path ~/Downloads/mwc-node-*-win-x64.zip -destinationpath .
PS C:\Users\konst\my_mwc_install> expand-archive -path ~/Downloads/mwc-wallet-*-win-x64.zip -destinationpath .
Volume serial number is 34E4-1A1F
C:.
├───mwc
└───mwc-wallet
```

Now your mwc-node is located at `~/my_mwc_install/mwc/mwc.exe` and your mwc-wallet is located at `~/my_mwc_install/mwc-wallet/mwc-wallet.exe`.

One common task is to send mined MWC from the mwc-wallet to the Qt wallet. In order to do that, the most convenient method is to use the "file based send". The mwc-wallet command to send is the following:

```
# mwc-wallet send -m file -d <location_to_save_file> <amount_to_send>
```

In order to receive it, you will need to click on "receive mwc by file". Select the file created in the last step. A new file saved in the same location as the file from the last step will be created with the suffix .response and this file can be finalized by the mwc-wallet with the following command:

```
# mwc-wallet finalize -i <location_of_response_file>
```

This will allow for sending of mwc from mwc-wallet into the Qt wallet.

## Start the node

Start the node for the first run.
```
> ~/my_mwc_install/mwc/mwc.exe
```

![](Install_mac_images/scr_node.png)


mwc-node has few commands. Run `~/my_mwc_install/mwc/mwc.exe help` to explore them.

Please keep your node running until we setup the wallet. You should be able to see that the node was able connect to the peers and download the chain.


#### Validate the node install

Please check that the node was able to create the files and download the data.

Check the files.
```
> cd ~
> tree /F .mwc
C:\USERS\KONST\.MWC
└───main
    │   .api_secret
    │   mwc-server.log
    │   mwc-server.toml
    │
    └───chain_data
        │   mwc.lock
        │
        ├───header
        │   ├───header_head
        │   │       pmmr_data.bin
        │   │       pmmr_hash.bin
        │   │
        │   └───sync_head
        │           pmmr_data.bin
        │           pmmr_hash.bin
        │
        ├───lmdb
        │       data.mdb
        │       lock.mdb
        │
        ├───peer
        │       data.mdb
        │       lock.mdb
        │
        └───txhashset
            ├───kernel
            │       pmmr_data.bin
            │       pmmr_hash.bin
            │       pmmr_size.bin
            │
            ├───output
            │       pmmr_data.bin
            │       pmmr_hash.bin
            │       pmmr_leaf.bin
            │
            └───rangeproof
                    pmmr_data.bin
                    pmmr_hash.bin
                    pmmr_leaf.bin
```

Please note the location of the:

log file: `~/.mwc/mwc-server.log`
config: `~/.mwc/mwc-server.toml`

Meanwhile feel free to check the logs at `~/.mwc/mwc-server.log`

If everything goes well, you shouldn't see anything logged at the "ERROR" level. Output from the following command should be empty
```
>  cat ~/.mwc/main/mwc-server.log | Select-String -Pattern  'ERROR'
```

**Note: It is expected that a single node and wallet only are running per host!**
If you try to run several instances, you will likely to see some errors.

You will need to wait a while for the node to download the blockchain data. When the download is complete, the UI will show the following: `Current Status: Running`.
If you see this status, congratulations, your node is running. We can start with a wallet setup.

## Init wallet

If you don't have an mwc-wallet instance, you will need to create a new one. Please note, if you already have an mwc-wallet instance, you can restore it through mnemonic or seed file. It is covered below.

Let's explore first what mwc-wallet can do by running:

```
> ~/my_mwc_install/mwc-wallet/mwc-wallet.exe --help
mwc-wallet 2.4.5
The Mwc Team
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
Any command can be explored by running `help <command>`. For example this command will show you details for 'init':  `~/my_mwc_install/mwc-wallet/mwc-wallet.exe help init`


To create the new wallet please run command below. We strongly recommend to setup the password for your seed.
```
> ~/my_mwc_install/mwc-wallet/mwc-wallet.exe init
Please enter a password for your new wallet
Password: Confirm Password: 20191111 18:13:13.180 WARN mwc_wallet_impls::seed - Generating wallet seed file at: ~/.mwc/main/wallet_data/wallet.seed
Your recovery phrase is:

cousin cargo avoid sk ....  fee surround valve prepare

Please back-up these words in a non-digital format.
Command 'init' completed successfully
```

Please store the recovery phrase in the secure place, preferably offline on a physical medium. The mnemonic will allow you to recover your funds in a new wallet even if your wallet files are destroyed.

If you already have a wallet, you can init it with your existing seed and resync it with a full node. Please note, if your wallet has any coins, you will only see them after a resyncing with the "restore" command.
```
> ~/my_mwc_install/mwc-wallet/mwc-wallet init -r
Please enter your recovery phrase:
phrase> cousin cargo avo .... ken coffee surround valve prepare
Please provide a new password for the recovered wallet
Password: Confirm Password: 20191111 18:17:49.394 WARN mwc_wallet_impls::seed - Generating wallet seed file at: ~/.mwc/main/wallet_data/wallet.seed
Your recovery phrase is:

cousin cargo avoid sk .... fee surround valve prepare

Please back-up these words in a non-digital format.
Command 'init' completed successfully

> ~/my_mwc_install/mwc-wallet/mwc-wallet check
Password:
20191111 18:22:25.359 WARN mwc_wallet_controller::command - Starting wallet check...
20191111 18:22:25.359 WARN mwc_wallet_controller::command - Updating all wallet outputs, please wait ...
20191111 18:22:25.394 WARN mwc_wallet_libwallet::internal::restore - Starting wallet check.
20191111 18:22:25.665 WARN mwc_wallet_libwallet::internal::restore - Checking 895 outputs, up to index 895. (Highest index: 895)
20191111 18:22:25.666 WARN mwc_wallet_libwallet::internal::restore - Scanning 895 outputs in the current MWC utxo set
20191111 18:22:25.739 WARN mwc_wallet_libwallet::internal::restore - Identified 0 wallet_outputs as belonging to this wallet
20191111 18:22:25.739 WARN mwc_wallet_controller::command - Wallet check complete
Command 'check' completed successfully
```

#### Validation

Please validate that your wallet created the files:

```
PS C:\Users\konst> cd ~
PS C:\Users\konst> tree /F .mwc
Folder PATH listing for volume Windows
Volume serial number is 34E4-1A1F
C:\USERS\KONST\.MWC
└───main
    │   .api_secret
    │   mwc-wallet.log
    │   mwc-wallet.toml
    │
    └───wallet_data
        │   wallet.seed
        │
        ├───db
        │   └───lmdb
        │           data.mdb
        │           lock.mdb
        │
        └───saved_txs
```

Please note the location of the:

logs : `~/.mwc/mwc-wallet.log`
config: `~/.mwc/mwc-wallet.toml`

Confirm that there were no errors during wallet initialization:

```
> cat ~/.mwc/main/mwc-wallet.log | Select-String -Pattern  'ERROR'
```

## Start Listener for the Wallet

In order to mine, mwc-wallet needs to be run in listening mode. The wallet will build the coinbase transaction for the blocks that your miner mines.

```
> ~/my_mwc_install/mwc-wallet/mwc-wallet listen
Password:
20191111 18:59:15.332 WARN mwc_wallet_controller::controller - Starting HTTP Foreign listener API server at 127.0.0.1:3415.
20191111 18:59:15.333 WARN mwc_wallet_controller::controller - HTTP Foreign listener started.
```
And your wallet will run until you interrupt it.

Congratulations, if you pass validation, your wallet is ready. Please keep it running for the duration of the time you are mining.

#### Validate

Please periodically check if logs don't have errors with:
```
> cat ~/.mwc/main/mwc-wallet.log | Select-String -Pattern  'ERROR'
```

Check if Foreign listener API runs well with the command:
```
> Invoke-WebRequest -UseBasicParsing -Uri http://localhost:3415/v2/foreign -Method POST  -Body '{"jsonrpc": "2.0", "method": "build_coinbase", "id": 1, "params": { "block_fees": 7000000}}'

StatusCode        : 200
StatusDescription : OK
Content           : {
                      "error": {
                        "code": -32602,
                        "message": "InvalidArgStructure \"block_fees\" at position 0."
                      },
                      "id": 1,
                      "jsonrpc": "2.0"
                    }
RawContent        : HTTP/1.1 200 OK
                    access-control-allow-origin: *
                    access-control-allow-headers: Content-Type, Authorization
                    Content-Length: 138
                    Content-Type: application/json
                    Date: Tue, 12 Nov 2019 06:35:52 GMT

                    ...
Forms             :
Headers           : {[access-control-allow-origin, *], [access-control-allow-headers, Content-Type, Authorization], [Content-Length,
                    138], [Content-Type, application/json]...}
Images            : {}
InputFields       : {}
Links             : {}
ParsedHtml        :
RawContentLength  : 138
```

## Setup mwc-node to run miner locally

Please update config for your mwc-node.

- Stop mwc-node if it is running. Please let mwc-wallet run in listening mode.
- Edit `~/.mwc/main/mwc-server.toml` with your favorite editor.

Change the value for `enable_stratum_server` to
```
#whether stratum server is enabled
enable_stratum_server = true
```
- Start mwc-node
```
> ~/my_mwc_install/mwc/mwc.exe
```

You are ready to to run your miner locally on the same host.

#### Validate

Check if there any errors are in the node logs
```
>  cat ~/.mwc/main/mwc-server.log | Select-String -Pattern 'ERROR'
```

Check if stratum is activated. The following line will be present in your log file if your node is configured correctly:
```
> cat ~/.mwc/main/mwc-server.log | Select-String -Pattern 'Stratum server started'
20191111 19:32:36.088 WARN mwc_servers::mining::stratumserver - Stratum server started on 127.0.0.1:3416
```

Verify that stratum is configured correctly with telnet:
```
> telnet  127.0.0.1 3416
{"id":"Stratum","jsonrpc":"2.0","method":"job","params":{"difficulty":1,"height":1151,"job_id":0,"pre_pow":"0001000000000000047f000000005dca547e0000072fb559593ebaed969308cefd2042c2e8384fbf62497c5a4f716bde7c710b9b34c1a4b411b494185053db66c9f7f661b9507d65a334495e7915372232d5362b2f2390b11ffcefef38ca3aed681a86a54643d8616a8c0e9d3b2c94d26772a0af3f1fcb38a62f84fa18aa906b94e02df1a2fde187512461dbdb14a8785bd4c20bada01d7f2d0732b8ed59902155c765286a81267e23bab3ae57a29ced0f62000000000000000000000000000000000000000000000000000000000000000000000000000008fe00000000000008fe0000000cf02a33580000019f"}}   
```

## Setup mwc-node to run a miner on a different host

Please update the config for your mwc-node.

- Stop mwc-node if it is running. Please let mwc-wallet run in listening mode.
- Edit `~/.mwc/mwc-server.toml` with your favorite editor.

Change the value for `enable_stratum_server` and `stratum_server_addr`
```
#whether stratum server is enabled
enable_stratum_server = true

#what port and address for the stratum server to listen on
stratum_server_addr = "0.0.0.0:3416"
```
stratum_server_addr needs to listen on 0.0.0.0 in order to accept connections from other hosts.

- Start mwc-node
```
> ~/my_mwc_install/mwc/mwc.exe
```

#### Validate node from local host

Check if there are any errors in the node logs
```
>  cat ~/.mwc/main/mwc-server.log | Select-String -Pattern 'ERROR'
```

Check if stratum is activated. The following line will be present in your log file if your node is configured correctly:
```
> cat ~/.mwc/main/mwc-server.log |  Select-String -Pattern 'Stratum server started'
20191111 19:32:36.088 WARN mwc_servers::mining::stratumserver - Stratum server started on 0.0.0.0:3416
```

Verify that stratum is configured correctly with telnet:
```
> telnet  127.0.0.1 3416
{"id":"Stratum","jsonrpc":"2.0","method":"job","params":{"difficulty":1,"height":1151,"job_id":0,"pre_pow":"0001000000000000047f000000005dca547e0000072fb559593ebaed969308cefd2042c2e8384fbf62497c5a4f716bde7c710b9b34c1a4b411b494185053db66c9f7f661b9507d65a334495e7915372232d5362b2f2390b11ffcefef38ca3aed681a86a54643d8616a8c0e9d3b2c94d26772a0af3f1fcb38a62f84fa18aa906b94e02df1a2fde187512461dbdb14a8785bd4c20bada01d7f2d0732b8ed59902155c765286a81267e23bab3ae57a29ced0f62000000000000000000000000000000000000000000000000000000000000000000000000000008fe00000000000008fe0000000cf02a33580000019f"}}   
```

#### Obtain my public IP.

Your miner will need to initiate a connection to your public IP. You can get your Public IP from the following site  [https://whatismypublicip.com/]

Please store your IP, you will need it to setup your miner and validate the setup.

#### Open port at Windows

Ensure the port is open and not being blocked by the firewall.
The easiest way is to disable the firewall.

#### Do you have a router? Map 3416 port for incoming connections

If you have a router you need to setup the port forwarding for incoming connections.

If you don't know how to do that, please do the search for the phrase: how to setup 'router brand' port forwarding.
For example: `how to setup Negtgear port forwarding`  will return you a link
[https://www.noip.com/support/knowledgebase/setting-port-forwarding-netgear-router-genie-firmware/]

We recommend you just map your router port 3416 to your device local IP address.

Here is how you can find your local IP for Windows [https://support.microsoft.com/en-us/help/4026518/windows-10-find-your-ip-address]

#### Validate if your port is open for INCOMING connections

Please verify that Port Tester shows that your port is open:
[https://www.yougetsignal.com/tools/open-ports/]

Here is how it looks when I didn't open port at my router, didn't disable firewall, or didn't run mwc-node with a proper setup.

![](Install_mac_images/port_close.png)

Here how it looks like when I did everything properly.

![](Install_mac_images/port_open.png)

**Please note! It doesn't make sense to continue with miner if your port is not open!** This tool works well and if your port is closed it means that the
 router, firewall or mwc-node are not configured correctly.

#### Validate stratum connection from your miner's host

If you can ssh to the miner host, please validate with telnet is miner can access the node:
```
> telnet  <MWC_NODE_PUBLIC_IP> 3416
{"id":"Stratum","jsonrpc":"2.0","method":"job","params":{"difficulty":1,"height":1151,"job_id":0,"pre_pow":"0001000000000000047f000000005dca547e0000072fb559593ebaed969308cefd2042c2e8384fbf62497c5a4f716bde7c710b9b34c1a4b411b494185053db66c9f7f661b9507d65a334495e7915372232d5362b2f2390b11ffcefef38ca3aed681a86a54643d8616a8c0e9d3b2c94d26772a0af3f1fcb38a62f84fa18aa906b94e02df1a2fde187512461dbdb14a8785bd4c20bada01d7f2d0732b8ed59902155c765286a81267e23bab3ae57a29ced0f62000000000000000000000000000000000000000000000000000000000000000000000000000008fe00000000000008fe0000000cf02a33580000019f"}}   
```

#### Node setup is DONE for access from the internet.

Congratulations, if you pass all validation steps, you are done with setup for mwc-node and mwc node.
You can finish miner setup.


## MINER

There are many miner that you can run. MWC miner 100% compartible with mwc miner. If you are mining for mwc, just redirect to mwc node.

#### Mwc miner

MWC clone of mwc miner you can get here [https://github.com/mwcproject/mwc-miner]
Please follow the instruction how to set it up.

#### GMiner

If you are rinning GMiner please run.
User name can have any value. You will see your miner in the mwc-node console under this name.

Your server IP should be 127.0.0.1 if you run your miner on the same host that you run mwc node and mwc-wallet.
Or you should use your mwc-node public IP if it is run on different host. Please check that your port is open and 'Validate stratum connection from your miner side' is passed.

To run in C31 mode:
```
miner.exe --algo mwc31 --server <NODE_IP>  --port 3416 --user WhatEverName
```
OR for C29d:
```
miner.exe --algo cuckarood29 --server <NODE_IP> --port 3416 --user WhatEverName
```

## Checking your coins

You might want to check how much coins you was able to main and see the output.

You can view the balance with `info` command
```
~/my_mwc_install/mwc-wallet/mwc-wallet.exe info
```

You can check your outputs with `outputs`
```
~/my_mwc_install/mwc-wallet/mwc-wallet.exe output
```



