# Distributed Message pool, Improved Coinjoin participation, Atomic Swap Marketplace


# Background.

We are going to introduce a distributed message pool, improved coinjoin participation and atomic swaps marketplace feature. This 
document is describing the overall design.

# Distributed messaging.
For atomic swaps marketplace and improved coinjoin participation we propose to create a "message pool". 

This can be achieve with traditional publisher/subscriber model. P2P network will provide the transport and the "message pool" data for the wallets.

For transport implementation we can use libp2p ( https://libp2p.io/ ) that support publisher/subscriber functionality.
This library exist on many planforms including rust and it is well maintained.

This library performance can handle more then required data. Polkadot and Ethereum 2.0 using libp2p as a primary transport
for node communication. The library can handle flooding attacks enough, so it can be adopted for the blockchain.

Also libp2p support direct p2p communication. So in the future wallets can potentially use it instead MQS or TOR. 

Currently libp2p doesn't designed to hide the connection address, but it should be possible to run it with TOR.
Here are the details: https://comit.network/blog/2020/07/02/tor-poc/

# libp2p initial use cases.

For this proposal, only mwc-wallets need to exchange messages toward other mwc-wallets, mwc-nodes aren't invovled.

Libp2p nodes maintain the libp2p network. In order to join the network a libp2p node need to join any other libp2p node. 

The problem is that a mwc-wallet only know its own mwc-node and is not able to discover other mwc-wallets on the network to communicate with.

Possible solutions:
1. Have a bootstrap node that know and maintain the addresses of other network participants.
2. Have MWC nodes and MWC wallets join the libp2p network.

Option 1 is a centralized approach and not desirable.
Option 2 add communication load to the MWC nodes but will greatly improve on decentralisation.

The mwc-wallet will join the libp2p network as follow:

1. mwc-node getting it's peer connections. As long one of its peer already joined the libp2p, it will be able to join the libp2p network.
2. If mwc-node doesn't found a mwc-node on the libp2p network, it will connect to the mwc-seed-node (The mwc-seed-nodes will be upgraded to participate 
in libp2p network)
3. mwc-wallet start and connect to the libp2p network with help of it's mwc-node.


# Atomic Swap Marketplace 

Atomic Swap Marketplace will use the publisher/subscriber model for message pool maintenance. Mwc-wallets, that are participating in the atomic swap marketpace need listen for new messages. 


### Placing/getting the offers. 

When qt-wallet publishing offer, it will send the message every few minutes.
```
{
  "peer_address" : "dkjsdskjh dsfakjhdfskljh", 
  "time" : 328768536,      // current time  
  "currency" : "BTC",
  ...  swap trade deal detals,
  
  "anchor_output": {
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

'anchor_output' is a special verifiable mwc-output that is published by the creater for each atomic swap offer. during last 24 hour. The purpose of this output
is to prevent massive flooding that is not easy to filter out. In order to flood, attacker will need to pay 
at least transaction fee to create such output. The honest players will need to pay transaction fee at least once in 24 hours as well. 

Qt-wallet that looking for the offer, will need to listen on the topic. During next 5-10 minute wallet will receive all
offers that are exist on the market. **It is expected that user will need to wait for 5-10 minutes until the offer 'message pool'
will be completed.** 

Please note, that before start listening, the wallet need to obtain from the node a list of outputs that was published during last 24 hours.
Any of those outputs can be Anchor Output.

Every offer can be quickly validated by checking if anchor_output=>commit does exist and anchor_output=>public_key
show the commit amount. The message can be calculated as 'peer_address' + 'time' from the offer message. The
anchor_output=>signature must match that message and public key.

### Anchor output

Currently every wallet has viewing public key that can be used to reveal output amount, but not allow to spend it.
All wallets has such root public key that is used for blockchain scanning to recognize spendable outputs. Normally 
the root public key is kept in the secret unless wallet want to disclosure it's balance and transactions.

For anchor output wallet need to create another derivative public key (anchor PK). As a result anchor output will be different from the 
rest, so the wallet can publish the anchor PK, to make possible to read the amount of the anchor output.
The ownership of anchor PK is proving the ownership of the anchor output.

mwc-wallet will need to be able to maintain such output, re spent it when swap offer need to be places. The amount 
will be less then 1 MWC. To create anchor output the wallet will create anchor PK from seed secret derivative and then use it 
for this output initialization. Normally mwc-wallet doesn't mix that anchor output with the rest spendable outputs
because of the privacy impact. Observer who knows Anchor PK can conclude that this output belong to that wallet. 

The not honest players can be banned by peer address or libp2p sender address. As a result the attacker traffic can be 
filtered out by the mwc-wallet. 

### Swap proof

For BTC, BCH, LTC, Dash, Doge and ZCash the locking accout is a pay-to-hash-script that looks like this:
```
OP_IF
	time
	OP_CLTV
	OP_DROP
	refund PK hash160
	OP_CHECKSIG
OP_ELSE
	OP_PUSHNUM_2
	cosign PK hash160
	redeem PK hash160
	OP_PUSHNUM_2
	OP_CHECKMULTISIG
OP_ENDIF
```
To build the script party need to know the lock time, three pablic keys that participate in the script.
Buyer own the Refund PK with private Key.  The seller owns Redeem PK with a private key.
The proof is the Pubic Key from the script, message and signature.

The proof will looks like:
```
{
  "id" : 1,
  "currency" : "BTC",
  "amount" : 0.2,
  "seller" : false,
  "lock_time" : 123455676,
  "refund_pk" : "hsdidsghfkgdgskhsslhjklshfkldfhfldskdfh", // pk or hash160
  "cosign_pk" : "dsksdjhaflkdshkdshdkshgkdgkdkjhfkshkfsd", // hash160
  "redeem_pk" : "a94356434385764965378654485694538654836", // pk or hash160
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

Please note, **any proof that publicly made is a privacy leak**. In order to proof participation in the swap trade, the wallet 
disclosure information abotu the swap trade and any disclosure by definition is privacy leak.

For example, if wallet provides the proof about BTC Swap deal, it disclosure the Locking Script details so another party can
validate that Swap trade really happens and this wallet really participated.

Disclosure details allows to reconstruct the script, calculate the Hash and Lock Address. By Lock address from BTC 
blockchain we can read the Locking amount (Swap Trade amoount), find from what address BTC funds was deposited and to what 
address BTC adress benefit from swap. Also it is possible to check if trade was finished successfully or the BTC amount was refunded back. 

There are no direct information about MWC transactions. But information about the swap trade and it's time can provide some information
about MWC part of the trade as well. For example it is known at what time the BTC funds was locked, so likely MWC funds was locked a little earlier.
It is know when BTC funds was redeem. The MWC funds was redeems a little later. Those fact might help to guess what 
inputs/iutputs participated in this swap trade on MWC side.

Also since BTC amount is known and exchange rate can be estimated, it is possible to guess the MWC amount at the swap deal. 
 
Because of MimbleWimble protocol it is still impossible to identify the wallet address.

On MWC side all those leaks will be covered with improved traceablity. It is expected the output from swap will go through the CoinJoin
and after that it will be really hard to trace anything.

#### Privacy impact, Anchor Output

Anchor Output will reveal amount and wallet that owns it. Because of that wallet will never mix it with other outputs.
If creation amount will be 1 MWC and fee is 0.005, that output will be good for swap trading during 200 days.

Also the outputs from Anchor output was created, need to be cleared with CoinJoin.

### Swap chat

With messaging and p2p connection we can organize p2p secure. It might be needed if
both parties want to talk and discuss the swap trade deal. Later it can be used to 
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

There were several ideas about tracability. So far the leading one is 'multikernel' transaction that is a bunch of independent transactions
that can be posted together.  

The idea that the wallets can merge there transactions instead of relay on dandelion. It is expected that the traffic is low
so dandelion will not work.

Also, this method will allow to post regular tansaction non tracable way as well, but it is not a primary use case, so 
it is not covered in this design now.

In order to filter out the non honest nodes, the wallet will need to listen messages for some time. That will allow to 
find out what peers are never response. Please note, peers that never response it can be honest peer that was last in the chain, 
so it is done, or it can be attacker. In both cases this peer need to be removed form the 'active' list.

## Checking traceability of the output.

Wallet can request the block that contain the output. For normal transactions wallet can assume that output untracable if
that block contain more then T kernels and T outputs.

Value of T need to be discussed, more is better. Value around 5 should give good enough results.

Please note, this assumption is expected that there was not observer who see the transactions separately. 

Also, over some time period, because of the block compaction, the number of kernels and outputs will decline. Because of that 
wallet will need periodically spend the outputs. 


## Messages

There will be two type of messages:

##### I am online message:
```
{
    "pub_key" : "834756342987563429867458654738947356"
}
```
This message contain just a public key of the wallet that willing to participate. Please note that this PK can be one time
temprary key not related to the wallet seed or anything else. 

Implicetly it will have p2p node ID. If connection to P2P network is private (Tor), no data about the wallet is leaked.
If connection is not protected by Tor the IP address can be leaked but inputs/outputs still will not be revealed.

##### Process the next message:
```
{
    "nonce" : 376824837256443,
    "recipient" : "rehjtgreioufgdh",  // pub_key  Hash
    "transactions" : "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
}
```
This message has the transaction that is added by somebody and encrypted with DH. Recipient with public key will be able to read the data.

Data is a multikernel transaction that is expected to be updated with additional data.

## Wallet's worklow.

T - number of joined transaction that concidered to be non tracable. Example: 5

1. Periodically wallet is checking if some of it's outputs are tracable. If at least one is yes, the wallet goes to the next step.
2. Wallet building a self spend transaction. It might have any number of inputs/outputs, but for simplicity it make sense to have one or more inputs and 1 output.
   - Note, instead of self spend, the walllet can put any transaction like a regular payment. 
3. Wallet joining the Pub/Sub topic 'CoinJoin' and listening on it.
4. Every 5 minutes the wallet is posting 'I am online message' with it's freshly generated Dalek PK to 'CoinJoin' topic. 
5. Wallet is listening on 'CoinJoin' and collecting the data
   - if it getting 'I am online message', the list of active wallets PK is updated. If list of active wallet is 3T, then wallet can initiate publishing of it's own transaction.
   - if it getting 'Process the next message', wallet can decode it, validate transactions. If transaction partly published, **we drop it (mission failed, need to retry)**. Otherwise go to step 7.
6. When wallet collected enough 2T transactions to publish, including it's own, it will publish all of them. **The mission is accomplished** for all participants.
7. If wallet gets 'Process the next message' with it's own transaction, the message will be republished to any random peer. 
   Because PK is known, the message can be encrypted with DH.
8. If wallet gets 'Process the next message' without transaction to mix, the message will be enriched with it's own transaction and republished 
   to random peer. Note, we can republish in case of failure, but I think it is not needed, see attacker response.
9. Periodically wallet checking if it transaction is published to the node. If it found at Tx Node, **the mission is accomplished**

Note, every 'add transactoin' requires to do kernel offset. As a result the deagregation will be impossible. 

Note, the first participant will pay smaller fee the the last one.  

## Attacking

Atacker can persue different goals. Let's check what attacker can do.

#### Make joining inefficient by publishing.

Attacker can advertise the many wallets and every time when it get's the transaction it can simply post it to the node.
As a result, no CoinJoin Happens.

Prevention:
If value of T is consensus, then starting participant can pay smaller fee, the next one will pay more to make the sum expected value.
The node will need to reject smaller fee transactions (will need to check the code). If T is 5, then the for 5 participans fees can be
0.003  0.006 0.008, 0.010, 0.011

As a result attacker will need at least add another transaction that pays the fees. Honest wallet will found later the tracability issue 
still exist and retry. But attacker will keep paying fees. As a result that will be costly for attacket to do that.

#### Make joining inefficient by dropping everything.

Dropping all request will prevent the Join happen normally. 

In this case the wallet can keep tracking of traffic abd try block p2p nodes that didn't answered. Durubg some time it will build a black list.
Attacker at least will need to change the p2p guids. But in this case wallet can prefer the peers that longer staing online.
Eventually the attacker nodes will be detected and black listed, or chаnged the addresses and become a new nodes. 
Only honest nodes will be in the peer set.

#### Observing 

Attacker can just observe the transaction before merge and try to build input/output mapping.

That will be relatively hard because:
1. Observer will need to behave as honest node. It should at least republish the traffic because otherwise other wallets will black list it.
2. If there are many observers, then observers will need to participate by including it's own transactions. That will be cost fees.
3. Because of 1 and 2, it is possible to have relatively small numbers of observers. As a result instead of T transactions, observer might spot
smaller number of the merget transactions. But in this case that still ok. Some fraction of outputs can be observed, but 
it is not enough to build the graph who-pay-who. Probability will be very low.   
