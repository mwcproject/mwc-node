# Reply attack mitigation


# Background.

With the cut through feature, the chain is somewhat vulnerable to the replay attack.
Some discussion threads can be found in mwc forum:

https://forum.mwc.mw/t/replay-attacks-and-possible-mitigations/7415

https://forum.mwc.mw/t/enforcing-that-all-kernels-are-different-at-consensus-level/

# Experiment
Some experiment is done to reproduce replay attack in dev's local environment.

## experiment to create an output with certain amount in the other wallet
With some tweak of wallet code, we were able to do this. 

i) send to a file tx.tx from wallet1(latest slate version 4 and lock_later was used), at the same time, modify the wallet code to save
this context with a different uuId, say, fake_uuid.

ii) receive the file tx.tx in wallet2 and response file tx.tx.response was generated.

iii) finalize tx.tx.response in wallet1

iiii) modify the uuid in tx.tx.response to fake_uuid and finalize this file in wallet1.
It will finalize. If output created in wallet2 by the first transaction has not been spent, posting will have duplicate UXTO error.

If the output in wallet2 was spent already, the posting will probably succeed.

# Proposal

Checking for duplicate kernels from node is straight forward but expensive, requiring
a hard fork.

Here we propose the following solutions to prevent replay-attack. It is a combined solution including update on both wallet and node, it doesn't require
hard fork or complicated change, and should cover most of the cases.

i)  Save the tx offset info to TxLogEntry and receiver wallet can check if duplicate offset exists. To keep backward compatibility,
this field will be optional. That will help if wallet is not restored form the seed in which case, offset is empty.

ii) Node can check duplication for tx kernel and outputs for last 2 week old block (node has that info). The output check will include
both UXTO and spent. We will add a cache for the spent output and keep them for 2 weeks. This will be soft fork for the node code.

iii) add height info when we build the output commitment. During the wallet scan, for the outputs with height difference more then 2 weeks, 
trigger self spend workflow. Of course, user will loose some tx fee for each self-spend.  There will be a self spend configuration on the QT 
wallet, user can opt out if they understand and want to take the risk.





