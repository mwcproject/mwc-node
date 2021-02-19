# Distributed Message pool, Improved Coinjoin participation, Atomic Swap Marketplace


# Background.

We are going to introduce a distributed message pool, improved coinjoin participation and atomic swaps marketplace feature. This 
document is describing the overall design.

# Distributed messaging.
For atomic swaps marketplace and improved coinjoin participation we propose to create a "message pool". 

This can be achieve with traditional publisher/subscriber model. P2P network will provide the transport and the "message pool" data for the wallets.

For transport implementation we can use libp2p ( https://libp2p.io/ ) that support publisher/subscriber functionality.
This library exist on many platforms including rust and it is well maintained.

Here is a description of the functionality that we are going to use:  https://docs.libp2p.io/concepts/publish-subscribe/

The peers discovery will be done by mwc-node.

Also libp2p support direct p2p communication and has Kademlia discovery protocol. So in the future wallets can potentially
use it instead MQS or TOR, but libp2p doesn't solve firewall problem. For now we are using TOR to mitigate that.

Currently libp2p doesn't designed to hide the connection address, but it should be possible to run it with TOR.
Here are the details: https://comit.network/blog/2020/07/02/tor-poc/

# libp2p initial use cases.

For this proposal, only mwc-wallets need to exchange messages toward other mwc-wallets, mwc-nodes aren't involved.

Libp2p nodes maintain the libp2p network. In order to join the network a libp2p node need to join any other libp2p node. 

The problem is that a mwc-wallet only know its own mwc-node and is not able to discover other mwc-wallets on the network to communicate with.

Possible solutions:
1. Have a bootstrap node, use Kademlia to discover and maintain the addresses of other network participants.
2. Have MWC nodes and MWC wallets join the libp2p network and use mwc-node peer discovery to join publish-subscribe network.

Option 1 is a centralized approach, include Kademlia, and not desirable.
Option 2 add communication load to the MWC nodes but will greatly improve on decentralisation.

The mwc-wallet will join the libp2p network as follow:

1. mwc-node getting it's peer connections. As long one of its peer already joined the libp2p, it will be able to join the libp2p network.
2. If mwc-node doesn't found a mwc-node on the libp2p network, it will connect to the mwc-seed-node (The mwc-seed-nodes will be upgraded to participate 
in libp2p network)
3. mwc-wallet start and connect to the libp2p network with help of it's mwc-node.
4. Periodically mwc-wallet requesting the list of the mwc-node peers, so it can maintain minimal number of connection to publish-subscribe network. 

# Atomic Swap Marketplace 

Atomic Swap Marketplace will use the publisher/subscriber model for message pool maintenance. Mwc-wallets, that are participating in the atomic swap marketpace need listen for new messages. 

TThe primary concern is how to mitigate the non honest players that can come to the market. Ideally user should pick the offer 
from the marketplace, start trading and finish the trade successfully.

Here are few aspects that addressing this problem.

1. Trust Score. Finishing successfully atomic swap trades with the wallet, will increase the trust score of the trader. Trader will be able to select finished
   swap trades to build it's own trust score. More trades with more amount will produce higher score. The trader will disclosure those trades amounts, 
   secondary currency, role in this trade (buyer or seller) and time when funds was locked. For every trade can be provided verifiable proof.

2. Integrity fee. In order to use the marketplace and publish the offer, the trader will need to pay the fees to miners. The fees need to be paid 
   daily. Once integrity fee is paid, one offer at a time can be published. When offer will be withdrawn from 
   the market place, another offer can be published (there will be some grace period between offers switch, about 15 minutes). The 
   integrity fee amount will depend on the offer amount and can't be smaller then a current transaction fee 0.005 MWC. 
   There are will be three fee levels:
   - Low: 1 pt or 0.01% of the trade amount.
   - Normal: 10 pt or 0.1% of the trade amount.
   - High: 50 pt or 0.5% of the trade amount.
<br/><br/>Please note, that fee doesn't guarantee that your offer will be accepted, it only guarantee that other wallets will see it at the marketplace.
     
3. Create lock transaction when the offer is published. When the atomic swap offer is published, the wallet will create the transaction that lock the 
   needed outputs into the wallet. As a result, the user will not be able to make a mistake by creating the offers
   that he can't satisfy, of accidentally spend the reserved funds from the wallet, while offer is on the marketplace. When offer
   will be withdrawn from marketplace, that locking transaction will be deleted and funds released.
   <br>Note, the funds will be locked locally on the wallet level, not on blockchain level. 
   
4. P2P Swap Trade (trade that we have now) will be cancellable only until locking step. As long as offer is accepted and initial
   message exchange is done, there will be now way to cancel the trade from UI. Sure, users can shout down the network or furn off the wallet.
   But in this case they will not be able to use the wallet.
   
5. Black list exchange. Every wallet will be able to maintain locally the blacklist of the traders. It is possible to recognize them by 
   'integrity output' and by trust score swap deals. Integrity output naturally creates a chain of spending. If the wallet will be online one a week,
   it will be able to track the blacklisted player for a while. That information can be exported and imported. As result users can 
   exchange with those blacklisted traders.
   

### Placing/getting the offers. 

When qt-wallet publishing offer, it will send the message every few minutes.
```
{
  "peer_address" : "dkjsdskjh dsfakjhdfskljh", 
  "time" : 328768536,      // current time  
  "currency" : "BTC",
  ...  swap trade deal detals,
  
  "integrity_output": {
      "commit" : "4376538763896586784364586",
      "public_key" : "6748369356438965854643856784356",
      "signature" : "47564387643857634875683476538765"
  }  
  "swap_proofs" : [
    {
      "id" : 1,
      "currency" : "BTC",
      "amount" : 0.2,
      "seller" : false,
    },
    ....
  ]
}
```
Every message is unencrypted and have the information about the atomic swap offer. Optionally user can use a past trade proof to build his reputation score.

'integrity_output' is a special verifiable mwc-output that is published with each atomic swap offer. Every receiver wallet can 
verify the ownership and fees for this integrity_output (fees will be checked by the all transaction in the blocks, because there is no way to 
validate transaction separately). Such output allows for wallets to set filtering rules, so the spam traffic will be filtered out. 
The purpose of this output is to prevent massive flooding that is not easy to filter out. In order to flood, attacker will need to pay 
at least transaction fee to create such output. The honest players will need to pay transaction fee at least once in 24 hours as well.
Also since fee are paid to miners, in case of spam attack to the marketplace, the miners will start getting more rewards,
more miners will come, and MWC network become stronger.

Qt-wallet that looking for the offer, will need to listen on the topic. During next few minute wallet will receive all
offers that are exist on the market. **It is expected that user will need to wait for few minutes until the offer 'message pool'
will be completed.** Proposed value for this time period is 5 minutes. In the future we might adjust that time if traffic will be too high.

Please note, that before start listening, the wallet need to obtain from the node a list of outputs that was published during last 24 hours.
Any of those outputs can be Integrity Output.

Every offer can be quickly validated by checking if integrity_output => commit does exist and integrity_output => public_key
show the commit amount. The message can be calculated as 'peer_address' + 'time' from the offer message. The
integrity_output => signature must match that message and public key.

### Integrity output

Currently every wallet has viewing public key that can be used to reveal output amount, but not allow to spend it.
All wallets has such root public key that is used for blockchain scanning to recognize spendable outputs. Normally 
the root public key is kept in the secret unless wallet want to disclosure it's balance and transactions.

For integrity output wallet need to create another derivative public key (integrity PubKey). As a result integrity output will be different from the 
rest, so the wallet can publish the integrity PubKey, to make possible to read the amount of the integrity output.
The ownership of integrity PubKey is proving the ownership of the integrity output.

mwc-wallet will need to be able to maintain such output, re spent it when swap offer need to be places. The amount 
will be less then 1 MWC. To create integrity output the wallet will create integrity PubKey from seed secret derivative and then use it 
for this output initialization. Normally mwc-wallet doesn't mix that integrity output with the rest spendable outputs
because of the privacy impact. Observer who knows Integrity PubKey can conclude that this output belong to that wallet. 

The not honest players can be banned by peer address or libp2p sender address. As a result the attacker traffic can be 
filtered out by the mwc-wallet. 

### Swap proof (swap score)

For BTC, BCH, LTC, Dash, Doge and ZCash the locking account is a pay-to-hash-script that looks like this:
```
OP_IF
	time
	OP_CLTV
	OP_DROP
	refund PubKey hash160
	OP_CHECKSIG
OP_ELSE
	OP_PUSHNUM_2
	cosign PubKey hash160
	redeem PubKey hash160
	OP_PUSHNUM_2
	OP_CHECKMULTISIG
OP_ENDIF
```
To build the script both party need to know the lock time, three public keys that participate in the script.
Buyer own the Refund PubKey with private Key.  The seller owns Redeem PubKey with a private key.
The proof is the Pubic Key from the script, message and signature.

The proof will looks like:
```
{
  "id" : 1,
  "currency" : "BTC",
  "amount" : 0.2,
  "seller" : false,
  "lock_time" : 123455676,
  "refund_pubkey" : "hsdidsghfkgdgskhsslhjklshfkldfhfldskdfh", // PubKey or hash160
  "cosign_pubkey" : "dsksdjhaflkdshkdshdkshgkdgkdkjhfkshkfsd", // hash160
  "redeem_pubkey" : "a94356434385764965378654485694538654836", // PubKey or hash160
  "message"   : <peer_address>_<current_timestamp>,
  "signature" : "8764356483645875687638653875638658456439865"
}
```

Proof evaluation:
1. Build a script, calculate the hash and locking address.
2. Request transactions for this address. It is expected that amount match with what is claimed for proof.
3. It is expected that all funds are redeemed or refunded for seller. And redeemed only for the buyer.
4. Check if the message is valid. The timestamp is much current time.
5. Check if the signature is valid.

#### Privacy impact, Atomic Swap Proof

Please note, **any proof that publicly broadcast is a privacy leak**. In order to proof participation in the swap trade, the wallet 
disclosure information about the swap trade and any disclosure by definition is privacy leak.

For example, if wallet provides the proof about BTC Swap deal, it disclosure the Locking Script details so another party can
validate that Swap trade really happens and this wallet really participated.

Disclosure details allows to reconstruct the script, calculate the Hash and Lock Address. By Lock address from BTC 
blockchain we can read the Locking amount (Swap Trade amount), find from what address BTC funds was deposited and to what 
address BTC address benefit from swap. Also it is possible to check if trade was finished successfully or the BTC amount was refunded back. 

There are no direct information about MWC transactions. But information about the swap trade and it's time can provide some information
about MWC part of the trade as well. For example it is known at what time the BTC funds was locked, so likely MWC funds was locked a little earlier.
It is know when BTC funds was redeem. The MWC funds was redeems a little later. Those fact might help to guess what 
inputs/outputs participated in this swap trade on MWC side.

Also since BTC amount is known and exchange rate can be estimated, it is possible to guess the MWC amount at the swap deal. 
 
Because of MimbleWimble protocol it is still impossible to identify the wallet address.

On MWC side all those leaks will be covered with improved traceability. It is expected the output from swap will go through the CoinJoin
and after that it will be really hard to trace anything.

#### Privacy impact, Integrity Output

Integrity Output will reveal amount and wallet that owns it. Because of that wallet will never mix it with other outputs.
If creation amount will be 1 MWC and fee is 0.005 MWC, that output will be good for swap trading during 200 days. The wallet will
keep creating a new integrity output every day paying the transaction fee.

Also the outputs from Integrity output was created, need to be cleared with CoinJoin.

### Swap chat

With messaging and p2p connection we can organize p2p secure chat. It might be needed if
both parties want to talk and discuss the swap trade deal details. Later it can be used to 
coordinate the trade.

## Atomic Swap marketplace attacking.

Attacker can flood the p2p network with messages. The network has it's own flood
prevention rules, but still attacker can create a lot of fake orders. 

The wallet will receive all of them. Wallet can only request the proofs. That is expected to be slow,
but eventually, after few minutes the peers that send 'dishonest' proof messages can be banned. 

The first time traders without proofs probably can do nothing with that. The reputation will need to be built.

Also every wallet can maintain the black list of peers, proofs and maybe something else. This list is local. We might export/import 
into the file so it will be sharable at the discord.

# Traceability

There were several ideas about traceability. So far the leading one is 'multikernel' transaction that is a bunch of independent transactions
that can be posted together.  

The idea that the wallets can merge there transactions instead of relay on dandelion. It is expected that the traffic is low
so dandelion will not work.

Also, this method will allow to post regular transaction non traceable way as well, but it is not a primary use case, so 
it is not covered in this design now.

In order to filter out the non honest nodes, the wallet will need to listen messages for some time. That will allow to 
find out what peers are never response. Please note, peers that never response still can be honest peer that was last in the chain. 
The options are: it is done, or it can be attacker. Fortunately both cases this peer need to be removed form the 'active' list.

## Checking traceability of the output.

Wallet can request the block that contain the output. For normal transactions wallet can assume that output untraceable if
that block contain more then T kernels and T outputs.

Value of T need to be discussed, more is better. Value around 5 should give good enough results.

Please note, this assumption is expected that there was no observer who see the transactions separately. 

Also, over some time period, because of the block compaction, the number of kernels and outputs will decline. Because of that 
wallet will need to track it's old outputs and periodically spend them. The time period will depend on network activity.

## Messages

There will be two type of messages:

##### I am online message:
```
{
    "pub_key" : "834756342987563429867458654738947356"
}
```
This message contain just a public key of the wallet that willing to participate. Please note that this PubKey can be one time
temporary key not related to the wallet seed or anything else. 

Implicitly it will have p2p node ID. If connection to P2P network is private (Tor), no data about the wallet is leaked.
If connection is not protected by Tor the IP address can be leaked but inputs/outputs still will not be revealed.

##### Process the next message:
```
{
    "nonce" : 376824837256443,
    "recipient" : "rehjtgreioufgdh",  // pub_key  Hash
    "transactions" : "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
}
```
This message has the transaction that is added by somebody and encrypted with Diffie Hellman. Recipient with public key will be able to read the data.

Data is a multikernel transaction that is expected to be updated with additional data.

## Wallet's workflow.

T - number of joined transaction that considered to be non traceable. Example: 5

1. Periodically wallet is checking if some of it's outputs are traceable. If at least one is yes, the wallet goes to the next step.
2. Wallet building a self spend transaction. It might have any number of inputs/outputs, but for simplicity it make sense to have one or more inputs and 1 output.
   - Note, instead of self spend, the wallet can put any transaction like a regular payment. 
3. Wallet joining the Pub/Sub topic 'CoinJoin' and listening on it.
4. Every 5 minutes the wallet is posting 'I am online message' with it's freshly generated Dalek PubKey to 'CoinJoin' topic. 
5. Wallet is listening on 'CoinJoin' and collecting the data
   - if it getting 'I am online message', the list of active wallets PubKey is updated. If list of active wallet is 3T, then wallet can initiate publishing of it's own transaction.
   - if it getting 'Process the next message', wallet can decode it, validate transactions. If transaction partly published, **we drop it (mission failed, need to retry)**. Otherwise go to step 7.
6. When wallet collected enough 2T transactions to publish, including it's own, it will publish all of them. **The mission is accomplished** for all participants.
7. If wallet gets 'Process the next message' with it's own transaction, the message will be republished to any 'random' peer (see below how to select honest random peer). 
   Because PubKey is known, the message can be encrypted with Diffie Hellman.
8. If wallet gets 'Process the next message' without transaction to mix, the message will be enriched with it's own transaction and republished 
   to random peer. Note, we can republish in case of failure, but I think it is not needed, see attacker response.
9. Periodically wallet checking if it transaction is published to the node. If it found at Tx Node, **the mission is accomplished**

Note, every 'add transaction' requires to do kernel offset. As a result the disaggregation will be impossible. 

Note, the first participant will pay smaller fee the the last one.  

## Attacking

Attacker can pursue different goals. Let's check what attacker can do.

#### Make joining inefficient by publishing.

Attacker can advertise the many wallets and every time when it gets the transaction it can simply post it to the node.
As a result, no CoinJoin Happens.

Prevention:
If value of T is consensus, then starting participant can pay smaller fee, the next one will pay more to make the sum expected value.
The node will need to reject smaller fee transactions (will need to check the code). If T is 5, then the for 5 participants fees can be
0.003  0.006 0.008, 0.010, 0.011

As a result attacker will need at least add another transaction that pays the fees. Honest wallet will found later the traceability issue 
still exist and retry. But attacker will keep paying fees. As a result that will be costly for attacker to do that.

#### Make joining inefficient by dropping everything.

Dropping all request will prevent the Join happen normally. 

In this case the wallet can keep tracking of traffic and blacklist p2p nodes that didn't answered. Eventually it will build a black list.
Attacker will need to change the p2p guids. But in this case the wallet will prefer the peers that longer staying online, so attacker node will be out for the session.
<br/>We can proof that eventually all attacker nodes will be detected and only the honest odes will be left. 

#### Observing 

Attacker can just observe the transaction before merge and try to build input/output mapping.

That will be relatively hard because:
1. Observer will need to behave as honest node. It should at least republish the traffic because otherwise other wallets will black list it.
2. If there are many observers, then observers will need to participate by including it's own transactions. That will be cost fees.
3. Because of 1 and 2, it is possible to have relatively small numbers of observers. As a result instead of T transactions, observer might spot
smaller number of the merged transactions. But in this case that still ok. Some fraction of outputs can be observed, but 
it is not enough to build the graph who-pay-who. Probability will be very low.   

