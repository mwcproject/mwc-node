# Atomic Swap Marketplace

Atomic Swap Marketplace will use the publisher/subscriber model for message pool maintenance. Mwc-wallets, that are participating in the atomic swap marketpace need to listen for new messages.

The primary concern is how to mitigate the non honest players that can come to the market spaming offers they don't plan to execute.

Here are features that should minimize this problem:

1. Integrity fee. In order to have the right to use the marketplace and publish offers, the trader will need to pay an integrity fee to the miners. This integrity fee will need to be paid daily. The
   integrity fee amount will depend on the offer amount and can't be smaller then a current transaction fee 0.01 MWC.
   There are will be three fee levels, for exemple:
    - Low: 1 bps or 0.01% of the trade amount.
    - Normal: 10 bps or 0.1% of the trade amount.
    - High: 50 bps or 0.5% of the trade amount.

2. Create local lock transaction when the offer is published. When the atomic swap offer is published, the wallet will create the transaction that lock the
   needed outputs into the wallet. As a result, the user will not be able to create offers if the funds are not available.
   <br>Note, the funds will be locked locally on the wallet level, not on blockchain level.

3. Atomic Swap trade will be only cancellable until locking step. As long as offer is accepted and initial
   exchange message is done, there will be no way to cancel the trade from UI. Users can still disconnect from his network or kill it's wallet process but in this case they will not be able to use the wallet until the atomic swap trade time out expire.

4. The counterparty that accept the offer will have to lock his funds first.

5. Black list. Every wallet will be able to locally maintain a blacklist of bad traders. It is possible to recognize them by
   'integrity fee' and by trust score swap deals.



### Placing/getting the offers.

When qt-wallet publishing offer, it will send the message every few minutes.
```
{
  "integrity_kernel": {
      "excess" : "6748369356438965854643856784356",
      "signature" : "47564387643857634875683476538765"
  }
    
  "peer_address" : "dkjsdskjh dsfakjhdfskljh", 
  "time" : 328768536,      // current time  
  "currency" : "BTC",
  ...  swap trade deal detals,
  
  ]
}
```
Every message is unencrypted and have the information about the atomic swap offer.

'integrity_kernel' is a regular transaction kernel with special fee, it must be published with each atomic swap offer. Every receiver wallet can
verify the ownership and fees for this integrity_kernel.
Such integrity fee allows wallets to set filtering rules, so the potentially spam offers, with low fees, can be filtered out.
The purpose of this output is to prevent massive flooding. In order to flood the network, attacker will need to pay
at fees for each offers. Since fees are paid to miners, in case of spam attack to the marketplace, the miners will start getting more rewards,
more miners will come, and MWC network become stronger.

It will take few minutes for Qt-wallet, open on market place, to receive all offers that exist.
Proposed value for this time period is 5 minutes.

In order to start listening, the wallet need to obtain from the node a list of kernels that was published during last 24 hours.
Any of those kernels with fee higher then minimal, can be used as Integrity kernel.

Every offer can be quickly validated by checking integrity_kernel => public_key.
The message can be calculated as 'peer_address' + 'time' from the offer message. The
integrity_kernel => signature must match that message and public key.

