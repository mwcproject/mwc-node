# Overview

As of mwc-node 4.0.0-beta.1, inbound tor connections are supported natively. By default TOR is off, but it is easy to turn on and in later releases we intend
make it on by default.

# Prerequisites and setup

You must install TOR and include it in your path. On mac, this can be done with the following command:

```
# brew install tor
```

On Ubuntu Linux:

```
# sudo apt install tor
```

On PC:

Download the tor browser from [The TOR Project](https://www.torproject.org/download/).
Then add the tor binary (tor.exe) to your path. For instructions on how to do that see [this](https://docs.alfresco.com/4.2/tasks/fot-addpath.html) or [this](https://www.architectryan.com/2018/03/17/add-to-the-path-on-windows-10/).

# Configuration

Once tor is installed and in your path, the configuration of your node can be done by modifying the mwc-wallet.toml file. You can generate a sample toml file
with the following command:

```
# mwc server config
```

This command will create the default toml file in your current working directory. It will be called mwc-server.toml.

This toml file will have the following tor configuration settings:
```
[server.tor_config]
tor_enabled = false
socks_port = 51234
tor_external = false
onion_address = ""
```
To enable tor, change tor_enabled to true.

Also, running in tor mode requires you to use a loop back interface, so you may need to modify the 'host' setting in mwc-server.toml. You may want to change
that to:

```
host = "127.0.0.1"
```
.
If you are using an extenral TOR instance, you can use the tor_extenral variable and set it to true. Your node will attempt to connect to the external tor
instance on the socks_port you specified. In addition, you should ensure that no other programs are binding to the socks_port that is specified.

The final parameter "onion_address" is only needed if you are using an external_tor process. It allows you to specify the onion address that you are using in
your extenral tor config.

# Upgrade

To upgrade, you will need to add the server.tor_config section to your old toml file. You can add the default values if desired, or like this example include
tor_enabled = true:
```
[server.tor_config]
tor_enabled = true
socks_port = 51234
tor_external = false
onion_address = ""
```

# TUI details

When running with TOR enabled you should see details like this in your TUI:

![TOR Inbound Image](https://github.com/mwcproject/mwc-node/blob/master/doc/Screen%20Shot%202020-08-01%20at%204.52.13%20PM.png "TOR Inbound")

You will notice that "Direction" indicates (TOR) when you have tor enabled. There are both inbound and outbound connections that are displayed in the image above.
You will also notice that you can both connect to .onion addresses (which are TOR enabled nodes) and IP based addresses.

# Conclusion

Inbound TOR connections is a powerful feature. It will enable a much greater degree of durability to the MWC network and improve one of the important properties of money. We are not aware of another project that has this feature integrated into the node in such a detailed manner. The network will be more durable because
it will be impossible for anyone to know exactly where the network is running. Even mining can move behind TOR if needed. For now it is probably more profitable
to mine with regular IP based connections due to latency though.
