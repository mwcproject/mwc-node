The TOR inbound feature allows inbound TOR connections. It is currently disabled by default, but can be enabled by setting the 'tor_enabled' variable in the
mwc-server.toml configuration file to true. Also, note that you will need to set the host to a loopback interface (i.e. 127.0.0.1) in order for tor to work.

Here are some basic steps to setup a new node with tor configured:

```
# mkdir testnode
# cd testnode
# mwc --floonet server config

Edit mwc-server.toml
[server.tor_config]
tor_enabled = true
socks_port = 51234

Edit mwc-server.toml
#The interface on which to listen.
#0.0.0.0 will listen on all interfaces, allowing others to interact
#127.0.0.1 will listen on the local machine only
host = "127.0.0.1"

# mwc

```

Also, note tor must be installed on the system and in the path prior to running this command. You can do this on mac with:

```
# brew install tor
```

And linux with:

```
# sudo apt install tor
```

On windows, see the torproject.org documentation for setup.

One thing to note is that in order for you to discover other TOR nodes, it is just like IP based discovery. You will need to have both nodes connected to another
that knows about both.

Also, you may enter tor servers in 'seeds', 'peers_preferred', 'peers_allow', or 'peers_deny' fields of the mwc-wallet.toml. When you do, so the expected
format is like this:
```
seeds = ["cdirjvwqxsgfnqbml62cf7ey7odb4c5ifvdzvp4rbf3nv3azopxg5pad.onion"]
peers_preferred = ["cdirjvwqxsgfnqbml62cf7ey7odb4c5ifvdzvp4rbf3nv3azopxg5pad.onion", "1.2.3.4:3413"]
```
Note: http is not included in the onion address.
