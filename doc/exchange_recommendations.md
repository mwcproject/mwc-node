# Overview #

This document is meant as a guide for exchanges to support MWC. Please note that all software is released under the apache license and has no warranty. Exchanges should thoroughly test everything and understand their architecture before they launch.

That said this is some information we have found useful to exchanges in preventing double spend attacks and block witholding attacks that may occur on MWC as with any other POW blockchain.

# Bounty #

The MWC Team is willing to help exchanges integrate MWC. For exchanges that successfully integrate MWC, use the Deposit by HTTPS and Withdrawal by File with immediate broadcast to the network like TradeOgre supports and the MWC Team tests and finds the implementation to be a good customer experience then a bounty may be paid. For exchanges that are interested then please contact the MWC Team.

# Deposit and Withdrawal Suggestions

The MWC Team recommends that exchanges use https for deposits and file for withdrawals. Based on experience this may greatly reduce customer support inquiries. Supporting a MimbleWimble based blockchain can be technically challenging for an exchange and require more work than other blockchains. However, if implemented well then it can flow very smoothly for users and the exchange.

The MWC Team is a fan of how TradeOgre has implemented withdrawals because they are broadcast immediately after user submission. This makes it very easy for users to buy and withdraw MWC extremely quickly.

The QT GUI wallet is widely used and easy for buyers, sellers, miners and almost all MWC users.

Deposits: **Deposit by HTTPS** is supported in the QT GUI wallet. The unsigned transactions are securely transferred between the user's wallet and the exchange's wallet. This increases the privacy of the deposit by not revealing anything about the transaction graph to the MWC peer to peer network.

Withdrawals: **Withdrawal by file** is supported in the QT GUI wallet. When implemented via https this has similar security and privacy benefits as https. A difference is that the user is able to be in control of the signing process and delivers a signed transaction via file upload that enables the exchange to immediately broadcast. This means the user does not need to have their wallet online to receive transactions which increases the user's security and privacy.

# Software that may be used to support MWC #

The mwcproject repository has two main wallets that are possible for exchanges to use:

mwc-wallet: https://github.com/mwcproject/mwc-wallet

and mwc713: mwc713: https://github.com/mwcproject/mwc713

The main difference between these wallets is that mwc713 supports receive by http(s), file, and mwcmqs, and keybase, while mwc-wallet supports http(s), file, and keybase. mwc-wallet is a fork of the mwc-wallet so it is much closer to mwc-wallet.

Exchanges that already support mwc-wallet may have an easier time supporting mwc-wallet than mwc713. The latest version of the wallet may have bug fixes so please keep up to date on changes.


# Double Spend Attacks #

One of the differences between the MWC network and the MWC network is that MWC has a much higher hashrate. This means that the MWC network is more susceptible to double spend and block witholding attacks than MWC. The MWC code that was forked does not handle these attacks at all and seems to rely on a high hashrate. Part of this is related to one of the differences between Mimblewimble and Bitcoin-like blockchains. In Mimblewimble, the network does not keep any transactions or spent outputs.
  
That is part of how it scales so much more easily than Bitcoin, but it means that wallet software and systems around that wallet software need to handle reorgs differently. The wallet has a separate state from the network. In the latest version of mwc-wallet and mwc713 most commands call scan and we attempt to keep the state of the wallet in exactly the same state as full node it is connected to.

<p>However, this is difficult to do. MWC also tried to do that but we found a number of cases where the state is not maintained accurately. We fixed all those that we could find, but ultimately the only way to ensure the exact state of the network is to recover the wallet from seed. Both wallets maintain a data file called the transaction log. In the transaction log, we attempt to update state of all transactions apporpriately in the latest wallet (3.1.x) for any new transactions processed by this version of the wallet.
  
  Even though the state of the transactions is updated in the transaction log, for an exchange it is not acceptable to rely on the transaction log data to determine if a deposit was a success or failure. Instead, exchanges should make a separate request to a full node before crediting the deposit to the user account. This can be done with the following HTTP request to a full node:

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

In addtion to this setup, it is possible to use some new settings a long with --min_conf in a single wallet to prevent double spends. See information about the new parameters here: https://github.com/mwcproject/mwc-wallet/blob/master/doc/change_outputs.md

# How many confirmations are needed #

Number of confirmations required is a personal decision that is up to the exchange. One can roughly estimate the cost of a double spend attack based on number of confirmations X value of the block reward. For example, if the block reward is 0.6, it would cost about 0.6 X 1000 = 600 MWC to do a double spend attack. Some exchanges have different number of confirmations for different amounts deposited. For small deposits, a lower number of confirmations might be acceptable and for higher amounts even more confirmations could be necessary.

Customers should understand the number chosen and decide which exchange to use based on that. We previously suggested 5000+ confirmations to exchanges but we now do not make any recommendation about number of confirmations to exchanges because it's highly dependent on the number of coins being deposited and it's a calculation the exchange should understand based on their own risk tolerances.

