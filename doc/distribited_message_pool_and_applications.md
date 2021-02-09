# Distributed Message pool,  traceability, Swap Marketplace


# Background.

We are going to introduce the improved traceability and swap marketplace feature. This 
document is describing the overall design, proc and cons.

# Distributed messaging.
For swap marketplace and improved traceability we need to maintain some kind "Message pool" with short live messages. 

With the traditional Messaging based on publisher/subscriber, we can achieve the same goal. In this case 
p2p network will provide the transport and the 'message pool' data can be built locally.

For transport implementation we can use libp2p ( https://libp2p.io/ ) that support publisher/subscriber functionality.
This library exist on many planforms including rust and well maintained.

Performance should be good enough to handle much more data. Polkadot and Etherium 2.0 using libp2p as a primary transport
for node communication. The library can handle flooding attacks enough, so it can be adopted for the blockchain.

Also libp2p support direct p2p communication, so wallets potentially can use it instead MQS or TOR. But that 
can be done later because we don't want to introduce too many changes at a time.

Currently libp2p doesn't designed to hide the connection address, but it should be possible to run it with a tor.
Tor provides proxy interface and libp2p can be conected. Here are the details: https://comit.network/blog/2020/07/02/tor-poc/

# libp2p initial use cases.

At current stage, only wallets need to exchange with the messages. There is nothing what nodes need to send/receive.

libp2p does maintain the p2p network. In order to join the network, the new node need to join any node from the network. 

The problem is that wallet knows only the node as a peer. And only nodes know more peers form the network. 

The possible solutions:
1. Have a botstrap node with know address.
2. Add wmc-node into the p2p network.

Choice number 1 is a centralized approach. The second coice will add some load to the nodes and will double the number of the nodes.

But very likely in the future we might adopt libp2p for nodes as well. As a result number two has more advantages. 

In this case the mwc-wallet p2p join workflow is.

1. mwc-node getting it's peer connections. As long node found the peer that joined p2p, it will join that peer.
2. If mwc-node doesn't found such mwc-node peer, DNS node will be used. The DNS nodes will be upgraded so they will participaate 
in p2p network.
3. mwc-wallet start and connecting to the mwc-node. It is expepcted that the mwc-node already joined p2p network at steps 1 and 2.
So mwc-wallet joining mwc-node.

# Swap marketplace 

Solution for Swap Marketplace will use the publisher/subscriber. Wallets that are participating in the swap marketpace 
need to provision and join the topic. That will allow p2p network route traffic optimally. 

For swap marketplace we will have one topic per swap secondary currency coin.

### Placing/getting the offers. 

When qt-wallet publishing offer, it will send the message every 5-10 minutes.
```json
{
  "peer_address" : "dkjsdskjh dsfakjhdfskljh",   
  "currency" : "BTC",
  ...  swap trade deal detals,
  "proof" : [
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
Every message is unencrypted and have the information about the offer and information about last trades. Wallet that
claims that proof exist, will need to show them  by demand.

Qt-wallet that looking for the offer will need to listen on the topic. During next 5-10 minute wallet will receive all
offers that are exist on the market. **It is expected that user will need wait for 5-10 minutes until the offer 'message pool'
will be filled.** 

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
```json
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

Please note, **all proofs are losing privacy**, I don’t think we can be better.

The user will be able to select what trades can be used for proofs.

### Swap chat

With messaging and p2p connection we can organize p2p secure. t might be needed if
both parties want to talk and discuss the swap trade deal. Later it can be used to 
coordinate the trade.

## Swap marketplace attacking.

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

