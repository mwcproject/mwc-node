# MWC Stratum Server extension for Mining Pool

## About

Normally Mining pools need extra functionality to prevent attacks. MWC Stratum Server extension provide additional layer for that. It is expected that 
additional layers of attacks preventions are in place as well. If needed, Stratum can be integrated with firewall to increase robustness.

## Configuration

Here is a default config for the Stratum Server of the MWC Node

```
################################################
### STRATUM MINING SERVER CONFIGURATION      ###
################################################
[server.stratum_mining_config]

#whether stratum server is enabled
enable_stratum_server = false

#what port and address for the stratum server to listen on
stratum_server_addr = "127.0.0.1:13416"

#the amount of time, in seconds, to attempt to mine on a particular
#header before stopping and re-collecting transactions from the pool
attempt_time_per_block = 15

#the minimum acceptable share difficulty to request from miners
minimum_share_difficulty = 1

#the wallet receiver to which coinbase rewards will be sent
wallet_listener_url = "http://127.0.0.1:13415"

#whether to ignore the reward (mostly for testing)
burn_reward = false

#activate workers activity tracking by IP and ability to ban incoming IP requests
ip_tracking = true

#Maximum number of connections. Stratum will drop some workers if that limit will be exceeded.
workers_connection_limit = 30000

#number of 'points' to ban an IP. worker get bad points for negative activity like flooding, no activity. Positive points can compensate negative ones.
ban_action_limit = 5

#Number of positive points for correct submitted work by miner.
shares_weight = 5

#During what time interval (ms) worker is expected to log in. To disable specify -1 (default value)
worker_login_timeout_ms = -1

#Auto unlock time period (seconds) for IP. How long stratum tracking IP related events
ip_pool_ban_history_s = 3600

# Maximum connection pace per IP (average time interval between connections from the same IP). To disable specify -1 (default value)
connection_pace_ms = -1

#IP white list. If IP belong to this list, it will be always accepted. Specify list of IPs, no mask or ranges are supported
ip_white_list = []

#IP black list. If IP belong to this list, it will be always banned. Specify list of IPs, no mask or ranges are supported
ip_black_list = []

# Number of tokio worker threads. -1, auto. You might put some large value here if your design does wait calls in the future handlers.
# NOTE: Removed form 3.2.0 release
# stratum_tokio_workers = -1
```


#### ip_tracking, ban_action_limit, shares_weight

ip_tracking activating stratum attacking prevention functionality. if ip_tracking is true, Stratum Server will collect 'good' and 'bad' events that 
comes from the workers at IP a address. If number of 'bad' events will be hight than number of 'good' by ban_action_limit values, this IP address will be banned.

Here are 'good' events: miner was logged in and authorized. Miner submitting shares.

Here are 'bad' events: miner didn't logged in, miner submitting some incorrect data or sending some unknown commands.

shares_weight parameter define how many point (or bad events) cost successful share submission event. Since share submission is most valuable positive event, 
we can tolarate shares_weight number of 'bad' events for that. 

If ip_tracking is false, then only ip_white_list & ip_black_list settings will be applicable. The rest will be disabled.
 
#### workers_connection_limit

Maximum number of connection that Stratum servers will accept. In case if connections number will be higher then workers_connection_limit, Server will
drop least valuable IPs. IP valuable is calculated as number of submited shared divided by number of workers. We want to drop first the workers 
that doesn't produce shares.

Please understand, that Server eventually validate the number of connections. So for some period of time it is possible to have number of connections higher then a limit.
During update workers will be disconnected by IPs, but those IPs will not be banned.

#### worker_login_timeout_ms

If your miners suppose to login, please specify this login timeout. Otherwise set it to <0 value, stratum will not track that.

If timeout set, Stratum will try to ban IPs from what workers anable to get an authorization during that time period.   

#### ip_pool_ban_history_s

How many seconds Stratum server will keep activity history. Or after what time period the ban will be filted.

Please note. Every event record takes 8 bytes. If you specify long time interval, please estimate if your have enough RAM for that.

#### connection_pace_ms

Minimum allowed average conneciton time interval from single IP. We don't want attacker flood Stratum Server form the single IP. That is why 
please setup reasonable average conneciton time interval. This setting will be applicable from 3-rd connection. Average value calculated based on last 10 
connections. 

Negative value disable that feature. If you decided to disable it, please think twice, it is possible to create thousands of connections from single IP and 
overload server before it will start checking to timeouts or closeing extra connection. 

Example: If I specify connection_pace_ms value as 1000 ms and run stratum test miner https://github.com/mwcproject/test
that will creates one connection every 100 ms.  As a result first 3 will be accepted, then connections 30,40,50,...  will be accpeted. The rest will be rejected.
 
#### ip_white_list

White list of IPs. Please note, it supoprt only IPs, no masks. Normally you shouldn't use it. We are thinking about testing or emergency use cases.

**Note:** White listed IPs can do anything, they never will be banned. 

#### ip_black_list

Black list of IPs. Please note, it support only IPs, no masks. Normally you shouldn't use it. We are thinking about emergency use cases.

**Note:** Black listed IPs are not reported by Rest API because API reports status of Stratum IP pool. IP checked for black list before.

#### stratum_tokio_workers

-- This option is removed form 3.2.0 release because mwc-node switched to async model. So there is no reasons to wait. Please migrate to sync/wait model.

## REST API  /v2/stratum

If ip_tracking is on, it make sense to check and manipulate with IPs.  This API using the same secret as Node Owner API. API will work with any settings, but 
real data will be provided only if Stratum server and ip_tracking are active (has 'true' value).

Every IP address has values

```
"ban"                  - flag is this IP is banned at the pool. Please note that IP White List and Black List override this value.
"failed_login"         - number of workers that wasn't authorized during 'worker_login_timeout_ms' inverval
"failed_requests"      - number of failed requests.
"ip"                   - IP address
"last_connect_time_ms" - last time when worker was connected
"ok_logins"            - numbers of workers that logged in
"ok_shares"            - numbers of submitted shares
"workers"              - current number of connected workers
``` 

#### Get IP pool data

Stratum server return every IP address that was seen during last 'ip_pool_ban_history_s' seconds.

banned - specify if you want to see banned or non banned IPs. null - see all values. 

```
curl -u mwcmain --request POST 'http://localhost:13413/v2/stratum' \
--header 'Content-Type: application/json' \

--data-raw '{
   "jsonrpc": "2.0",
   "method": "get_ip_list",
   "params": {
  	  "banned": null,
	},
	"id": 1
}'

Respond:
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": {
    "Ok": [
      {
        "ban": false,
        "failed_login": 0,
        "failed_requests": 0,
        "ip": "192.168.1.2",
        "last_connect_time_ms": 1584495759831,
        "ok_logins": 0,
        "ok_shares": 0,
        "workers": 60
      }
    ]
  }
}
```

#### Get single IP  

```
curl -u mwcmain --request POST 'http://localhost:13413/v2/stratum' \
--header 'Content-Type: application/json' \
--data-raw '{
   "jsonrpc": "2.0",
   "method": "get_ip_info",
   "params": {
  	  "ip": "192.168.1.2"
	},
	"id": 1
}'

Respond:
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": {
    "Ok": {
      "ban": true,
      "failed_login": 0,
      "failed_requests": 99,
      "ip": "192.168.1.2",
      "last_connect_time_ms": 1584495763878,
      "ok_logins": 0,
      "ok_shares": 0,
      "workers": 0
    }
  }
}
```

#### Clean IP data (unban IP)

```
curl -u mwcmain --request POST 'http://localhost:13413/v2/stratum' \
--header 'Content-Type: application/json' \
--data-raw '{
   "jsonrpc": "2.0",
   "method": "clean_ip",
   "params": {
  	  "ip": "192.168.1.10"
	},
	"id": 1
}'

Respond:
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": {
    "Ok": null
  }
}
```

## Configure your OS

mwc-node doesn't manage your TCP connections, including timeouts. As a result you have to configure your OS to handle dropped connections well.

### Test (optonal step for verification)

First please check how Stratum handle dropped connections before your changes.

1. Install miner simulatior from https://github.com/mwcproject/test   Check readme for location and usage.
2. COnfugure startum server and start the node.
3. Start miner simulatior with few thousands of connections.
4. Wait untill they will be created.
5. Unplug your network cable or turn off network. That will make all your connections stale.
6. Check how long it takes for the node to drop all connections.

### Solution for Ubuntu

Note! Before modify your OS please do search and understand what you is fing first.

```
sudo vi /etc/sysctl.conf
``` 
Update keep alive settings. Here is a settings for ip4. Check if you need to update ip6 as well.
```
net.ipv4.tcp_keepalive_time = 20
net.ipv4.tcp_keepalive_intvl = 5
net.ipv4.tcp_keepalive_probes = 2
```
Update data transmission setting. Step 1, just reduce number of retry. Value 6 will give you about 12 or more seconds to disconnect from dropped value. 
```
net.ipv4.tcp_retries2 = 6
```
data transmission setting. Step 2. Prev step makes your read/write timeput 12 seconds or MORE.  More can be up to hours.
The problem that initial RTO value that is normally 200ms is depend on socket connection quality. Slower network, larger this value.
As a result 'fast' connections will be dropped after 12 seconds, but for slow connections, it can take hours to drop and that can be critical.

to view your connections starting rto values: 
```
> ss -i
.....
tcp                               ESTAB                                 0                                   0                                                                                      192.168.1.14:3416                                                                  192.168.1.10:58988                               
	 cubic wscale:7,7 rto:220 rtt:18.835/19.578 mss:1338 pmtu:1500 rcvmss:536 advmss:1448 cwnd:10 bytes_acked:590 segs_out:1 segs_in:3 data_segs_out:1 send 5.7Mbps lastsnd:3180 lastrcv:15536 lastack:3104 pacing_rate 11.4Mbps delivery_rate 147.1Kbps app_limited busy:76ms rcv_space:14600 rcv_ssthresh:64076 minrtt:11.134    
tcp                               ESTAB                                 0                                   0                                                                                      192.168.1.14:3416                                                                  192.168.1.10:53400                               
	 cubic wscale:7,7 rto:3288 rtt:408.146/719.897 ato:40 mss:1338 pmtu:1500 rcvmss:536 advmss:1448 cwnd:10 bytes_acked:940 bytes_received:188 segs_out:10 segs_in:12 data_segs_out:6 data_segs_in:4 send 262.3Kbps lastsnd:3140 lastrcv:7132 lastack:584 pacing_rate 524.5Kbps delivery_rate 40.5Kbps app_limited busy:3436ms retrans:0/2 rcv_space:14600 rcv_ssthresh:64076 minrtt:6.949
....
```
In this example one socket rto is 220, another one about 15 times higher. So read/write timeouts will be propotrional.

It is possible to specify rto_min value for network route.
 

**Reference:**

https://webhostinggeeks.com/howto/configure-linux-tcp-keepalive-setting/

https://pracucci.com/linux-tcp-rto-min-max-and-tcp-retries2.html

https://unix.stackexchange.com/questions/210367/changing-the-tcp-rto-value-in-linux
