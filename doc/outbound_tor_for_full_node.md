# Overview

As of mwc-node 3.2.3, tor (via socks5 proxy) outbound connections are supported. This feature will allow a full node to sync without leaking any IP data. ISPs and
other nodes will not know you are connecting to an MWC node. This is an important step towards improved privacy for MWC.

# Setup

Configuration of the socks5 proxy is simple. If you install a new mwc-node (with the command ```# mwc server config```, you the sample configuration file will show
you an example of a socks5 configuration:

```
#socks5 proxy address.
#socks5addr = "127.0.0.1:9050"
```

In the sample, config, if the second line above is uncommented, the mwc-node will attempt to connect to the loop back interface (127.0.0.1) on port 9050. This is
the default port for TOR. If you are running tor on another port, you can change the configuration value to the port you have tor running on. To install tor
on MacOS:

```# brew install tor```

and on linux:

```# sudo apt install tor```

On windows, you can download the tor browser (which will also install the tor socks5 proxy) from https://www.torproject.org/.

In addition to this, if your node is running on a public IP or you have port forwarding enabled, you will want to disable that so that no inbound connections are
accepted unless you are ok with those inbound connections which will know your IP address.

# Migration

Migration is simple since the socks5 proxy option is optional, an older configuration file will still work with the newer version of the node and if you wish to
use the socks5addr parameter, it can simply be added.

# TODO

The next logical step is to enable inbound TOR connections. That will greatly improve the durability of the MWC network as the entire network may operate without
anyone knowing where any of the nodes are located. That will be the next task that is worked on.
