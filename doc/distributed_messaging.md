# Distributed messaging (distributed message pool).

# Background.

We are going to introduce a distributed message pool, that will be used for improved coinjoin participation and atomic swaps marketplace feature. This
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

# Flooding prevention 

In order to prevent the flooding by non honest users, mwc network will use the integrity fee. In order to have the right to use the 
messaging network, the wallet will need to pay an integrity fee to the miners. This integrity fee will need to be paid daily. The
network transport will accept any fee that is higher than 10 fee basic points. Currently the minimal fee will be 0.01 MWC.

Every message must have a proof that integrity fee is paid and transaction with 'integrity_kernel' exist on the blockchain. The traffic 
per single kernel will be limited to one message per 15 seconds.

In order to flood the network, attacker will need to pay a lot of fees to keep the traffic heavy. Since fees are paid to miners, in case of spam 
attack to the libp2p messaging, the miners will start getting more rewards, more miners will come, and MWC network become stronger.


### Integrity kernel and privacy leak mitigation

Integrity kernel is a regular transaction kernel with fee higher from regular transactions. But because kernels are used for proofs, they are
not private and can be easily trackable.

This Integrity kernel will be generated with a self spend transaction. As a result, the wallet will be able to control all public and private keys that was used for
generation of this kernel. With known private keys, the wallet can generate the signature to proof ownership of the kernel.

To mitigate privacy leaks from those integrity kernels, mwc-wallet will maintain the outputs from transactions separately. The wallet will create a separate special hidden account for those outputs.

An initial deposit amount for the integrity fee acount will need to be set by the user, example 1 MWC and assuming integrity fee for offers is 0.01 MWC, that output will be good for swap trading during 100 days.


# Changes

## rust-libp2p-tokio--socks5

This is a small library that provide connection to the TOR socks service. Plus it add tor support to libp2p multiaddress.
There was few changes that was made:
- It use default TOR socks port 9050. I make that port setting to be mandatory. The problem is error reporting. There is no way to
  find that nothing works because of that port.
- ping example was adopted to our needs.

## libp2p

Libp2p  dpesn't work out of the box, but still I wasn't be able to find anything better. Because of that we adopted gossipsub and enhance it to meed our needs.
For MWC project we are planning to use gossipsub only with TOR addresses because of the privacy.

Please check the explanation of the gossipsub first:  https://docs.libp2p.io/concepts/publish-subscribe/
It is our starting point. Also please note, libp2p gossipsub original design in not responsible for peer discovery. MWC implementation fixing that.

Here are changed that was made:
- Every peers got additional String address. Because we are using only TOR connections, with address it is possible to call back to any peer.
  libp2p using IP address for income connections, but it is not for the code that we are using. Those libp2p components are expected to work inside local network.
  With TOR address, it needed, that can limit can be lifted as well.
- gossipsub reserved topic "Peers" for internal needs. Every gossipsub respond back on this topic to it's own peer with a full poeer list.
  That response happens:
    * After initial connection. That list can be used for bootstraping (see below the details).
    * Periodically node updates random peer with it's peer list (There is no request to the node for list of peers).
- peer blacklist logic is changed. Original libp2p design maintain blacklisted_peers that is managed by this service caller.
  Originally libp2p kept connection from blacklisted nodes, but ignore traffic from them. Here are the MWC features.
    * blacklist peers are is managed by the service caller and but service. Service add peer to the ban list if:
        1. Peer sent us invalid message. First invalid will be classify as attack, the message will be dropped and peer blacklisted.
        2. Peer violate integrity rules (for example, sending spam).
    * Blacklisted peers will be disconnected. There is no reasons to maintain connection.
    * If blacklisted connection, it will be disconnected as early as possible. But first connection will be accepted, the protocol
      exchange will be finished. We need to do that to recognize the peer by id.
    * Blacklisted node has expiration time. By default it is one hour. Timeout is necessary because peer can be blacklisted because of network fluctuations
      or user mistakes. After some time connections can be restored. mwc-node using the similar rules and so far it works fine.
- Message validation and routing logic was changed. Original gossipsub functionality has feature to validate the income messages. The messages are stored in the cache,
  then after validation, they will be forwarded to the network. The peer score wil be updated depend on validation results.  
  The problem is that it is not finished, there is no hook to get the data for validation. The only workflow that is goes form the node to the caller are the messages
  that suppose to be what caller is subscribed to. The change is: if massage validation is on, caller will get all the messages and it is expected that caller will
  validate all of them and process only that are interesting for the caller. Since caller knows the topics for subscription, it can be done.
- Nodes are responsible for limiting connections to peers. In order to balance the network, node will start closing connections to some peers randomly
  until the total number of connection will be below double 'mesh_n_high' value. mesh_n_high default value is 12. So the node will maintain 24 or less connections.
- Note, the node will always accept a new connection, send back the list of the peers. Limiting connections to peers happens eventually. This method
  should allow to bootstrap and maintain distributed network.
- gossipsub connection keep alive had a timeout 30 seconds. Even example didn't work well. I changed keep_alive value to "Yes".
  The node will close extra connection if the will be too many of them.
- Bootstraping process is on the caller. It is caller responsibility to find the node that belong to the network and join it.
  Normally it is enough to find one node that is already in the network. It will

Note:
- NWC network is not part of the message. It is not needed because if by mistake the connection will be made to the wrong network,
  the node will ba banned out because integrity commit values will be invalid. Since it happens naturally, we don't want to add anything extra.

## mwc-node

- Add setting 'libp2p_port': libp2p gossipsub tor socks port for listeniong. It is licated in to the config file. Default values: 3417 for mainnett, 13417 for floonet.
- Tor config provisioning get a new line `HiddenServicePort  81 127.0.0.1:<libp2p_port>`
- Add new mode mwc-node/servers/src/mwc/libp2p.rs.  Here located all caller to gossipsub logic:
    * `add_new_peer( peer: &PeerAddr )`  - Method that mwc-node server calls when it discover the peers with onion address. Probably they are gossipsub nodes, so we should try them.
    * `pub async fn run_libp2p_node( tor_socks_port: u16, onion_address: String, libp2p_port: u16 ) -> Result<(), Error>`  - libp2p main method. There all logic happens:
        - Building network transport, initialize the swarm and start listening
        - validate all income message. For every message response with `gossip.report_message_validation_result` call
        - Processing Peer list from the nodes that it was connected. That list will be kept just in case we will need more peers.
        -
    * logs filter include messages form 'libp2p'
- Get `get_libp2p_peers` for the node. mwc-wallet will use it for the bootstrap.
- Update seeds with onion addresses. Now DNS understand that onion  address is good to connect, the normal DNS records will be connected to IPs 

## mwc-wallett

- Add 'integrity' command that allow to manage integrity transactions. Sign messages with integrity kernel.

