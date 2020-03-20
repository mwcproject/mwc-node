# Overview #

This document is meant as a guide for exchanges to support MWC. Please note that all software is released under the apache license and has no warranty. Exchanges should thoroughly test everything and understand their architecture before they launch. That said this is some information we have found useful to exchanges in preventing double spend attacks and block witholding attacks that may occur on MWC as with any other POW blockchain.

# Software that may be used to support MWC #

The mwcproject repository has two main wallets that are possible for exchanges to use:

mwc-wallet: https://github.com/mwcproject/mwc-wallet

and mwc713: mwc713: https://github.com/mwcproject/mwc713

The main difference between these wallets is that mwc713 supports receive by http(s), file, and mwcmqs, and keybase, while mwc-wallet supports http(s), file, and keybase. mwc-wallet is a fork of the grin-wallet so it is much closer to grin-wallet. Exchanges that already support grin-wallet may have an easier time supporting mwc-wallet than mwc713. Please ensure you have the latest version of this software running in production.


# Double Spend Attacks #

<p>One of the differences between the GRIN network and the MWC network is that GRIN has a much higher hashrate. This means that the MWC network is more susceptible to double spend and block witholding attacks than GRIN. The GRIN code that was forked does not handle these attacks at all and seems to rely on a high hashrate. Part of this is related to one of the differences between Mimblewimble and Bitcoin-like blockchains. In Mimblewimble, the network does not keep any transactions or spent outputs. That is part of how it scales so much more easily than Bitcoin, but it means that wallet software and systems around that wallet software need to handle reorgs differently. The wallet has a separate state from the network. In the latest version of mwc-wallet and mwc713 most commands call scan and we attempt to keep the state of the wallet in exactly the same state as full node it is connected to.

<p>However, this is difficult to do. GRIN also tried to do that but we found a number of cases where the state is not maintained accurately. We fixed all those that we could find, but ultimately the only way to ensure the exact state of the network is to recover the wallet from seed. Both wallets maintain a data file called the transaction log. In the transaction log, we attempt to update state of all transactions apporpriately in the latest wallet (3.1.x) for any new transactions processed by this version of the wallet. Even though the state of the transactions is updated in the transaction log, for an exchange it is not acceptable to rely on the transaction log data to determine if a deposit was a success or failure. Instead, exchanges should make a separate request to a full node before crediting the deposit to the user account. This can be done with the following HTTP request to a full node:

```$ curl https://mwc713.mwc.mw/v1/chain/outputs/byids?id=<id> ```

Plese note that this command will only return data for outputs that have not been spent. So make sure to run this command before spending the outputs.

This command should only be run after sufficient confirmations are obtained. In order to find the output for a deposit, this command can be used in mwc-wallet:

```mwc-wallet txs -i <tx_index>```

Among other things, the output for this transaction can be obtained.

All outputs from the deposit wallet should be swept to a withdrawal wallet after sufficient confirmations. The following command can be used to do this:

```mwc-wallet send --min_conf 5100 -d <destination> <amount>```

This command will sweep all full confirmed funds from the deposit wallet to a withdrawal (or cold storage) wallet. This procedure will ensure that:

1.) All deposits are checked after sufficient confirmations before crediting to the customer account.
2.) All available funds are transfered to the withdrawal wallet as soon as they are available. Note that the min_conf should be higher than your confirmations required to accept a deposit.

Sweeping should be done on a regular basis or as needed by the exchange.

# How many confirmations are needed #

Number of confirmations required is a personal decision that is up to the exchange. You can roughly estimate the cost of an attack based on number of confirmations X value of the block reward. For example, if the block reward is 0.6, it would cost 0.6 X 5000 = 3000 MWC to do a double spend. Some exchanges have different number of confirmations for different amounts deposited. Customers should understand the number choosen and decide which exchange to use based on that. We have been suggesting 5000+ confirmations to exchanges, but it's really a question of risk and amounts deposited. We have had reorgs of up to 120 blocks but there's no guarantee that a higher number won't occur at some point.

