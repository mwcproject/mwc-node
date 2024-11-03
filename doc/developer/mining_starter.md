1, In order to mine from a developer's perspective, we need to have at least two MWC instances. The best way of handling this is to 
create a mwcusers directory, under which two separate directories for user1 and user2 are created. Then cd to the directories  
for user1 and user2, do: 
> mwc server config

The above will set up the environment so that running more than 1 instance on the same machine won't hit the locking issue. After 
this run 
> mwc 

to start two MWC instances. 

2, Get another terminal, then set up the wallet by doing: 
> mwc wallet init -h
> mwc wallet listen

3, Again get another terminal, go to the directory for user1, update in file mwc-server.toml: 
change enable_stratum_server from false to true

4, Build mwc-miner, and then run it (more updates later)

5, To verify if mining is going on, look for mwc-miner.log.
