
- Title: `Non-Interactive Transaction and Stealth Address`
- Authors: [Suem](mailto:suem.cc@protonmail.com)
- Start date: Nov. 12, 2020
- Main implementation PR: [mwcproject/mwc-node#24](https://github.com/mwcproject/mwc-node/pull/24)

---

## Summary
[summary]: #summary

Interactive/online transaction is a novel transaction type for crypto fans, when they first see Mimblewimble blockchains. After some trying out, most of them would feel inconvenient especially when the recipient is not online or can not retrieve the private key at a moment. Recently, there are some progress in this domain, which is breaking the ice to bring our accomplished experience back into Mimblewimble chain.

- [One-sided MW Transactions for LTC Extension Block](https://github.com/litecoin-project/lips/pull/13), Work In Progress, David Burkett
- [Tari-specific Extensions to Mimblewimble](https://rfc.tari.com/RFC-0201_TariScript.html), Cayle Sharrock
- [Mimblewimble Non-Interactive Transaction Scheme](https://eprint.iacr.org/2020/1064.pdf), Gary Yu

## Motivation
[motivation]: #motivation

To improve the common user experience and further consolidate the privacy of MWC, we propose to integrate both one-sided payment (non-interactive transaction, or realtime off-line transaction) feature and the stealth address feature. After these feature released, MWC user will get an address for the wallet, which enable the coin receiving by publishing this address to the sender, in the same time, the published transaction data will never disclose this address info for other people.

## Community-level explanation
[community-level-explanation]: #community-level-explanation

With this feature, the wallet sending/receiving will be much easier, the payee share his/her wallet address string to the payer, this string is probably something like 49kwm9zLYyCP1LvP97mmHr838vjU76iChRk49fraNwCGAXG4h1sUt6bhdvUQ3AWgGahLVrBuAkEm5QwegKCS5G52Gqs4zpt, and the payer sends some coins to this address, and wait for a few of block confirmations, that's all. Once the payer knows the payee's wallet address string, the payee does not need do anything for receiving the payment. 

The wallet can be receiving-only or view-only, so that the owner is able to protect his/her private key in a separated place for safety. 

All the original privacy characteristics in Mimblewimble are still kept, the transactions are completely opaque.

## Reference-level explanation
[reference-level-explanation]: #reference-level-explanation

We're going with Gary's paper for this feature. For the convenience, we use NIT(Non-Interactive Transaction) as the abbreviation in the remaining part of this document. All the technical aspects are detailed in the paper already. We could address some special design here in the future if have. But at this time, I would like to summarize some comparing between all these one-sided(non-interactive) transaction schemes.

### Comparing Among LTC LIP-004, Tari Script, and NIT

Before that, we should know that Mimblewimble is in different level for MWC, LTC, and Tari:

- Mimblewimble is a native protocol for MWC.
- Mimblewimble is an Extension Block for BTC. Refer to LTC-003.
- Mimblewimble is the basic layer protocol for Tari, but with Bitcoin style script supported.
 
Some could feel confusing for Mimblewimble and one-sided(non-interactive) transaction. The point is that implementation of Mimblewimble does NOT mean it must support one-sided(non-interactive) transaction, these are 2 different things. For example, we see that
 LTC planed to integrate Mimblewimble as Extension Block, which is being developed since Dec. 2019, and will be activated 1 year from the day the feature released. (not released yet till today.) The related LIPs in LTC are LIP-002 and LIP-003. In LIP-003, the “MW to MW transactions” chapter, it says "Once inside the extension block, MW to MW transactions will follow traditional MW protocol rules.”  that means it will use the Mimblewimble interactive transaction. The LTC Mimblewimble one-sided(non-interactive) transaction is LIP-004, which is still in draft stage. It’s not clear when LTC will finalize it and when it will be planned to be released.

About the LTC Mimblwimble, LTC will use EB (Extension Block) for Mimblewimble. The LTC transaction need an additional pegged-in/pegged-out assistant transaction when transiting coins between the main block side and the EB side. In comparing, MWC and Tari will use main block only, no EB needed. BTW, LTC Mimblewimble EB feature has been developed almost one year since 2019.12, we could suppose it will be released in the end of 2020, then that LTC soft fork could be at the end of 2021. In comparing, MWC has been released since Nov. 11, 2019 for basic Mimblewimble protocol, and plan to deliver NIT feature as a hard fork in H2 of 2021. Tari, as a community project, does not have a clear plan to be released, we could expect it in 2021, but not clear whether the Tari script will be in the first release of its mainnet. 

Regarding the privacy, as described in LTC LIP-003, for implementation of pegged-in/pegged-out transaction, a special address in main block will be used to receive/send out, that means it’s transparent for the blockchain about who is using LTC Mimblewimble extension and even how much value, just by tracking this special address. Another aspect, in my personal view, LTC with Mimblewimble extension will be quite similar as Zcash, which supports both anonymous shielded and pseudonymous transparent transactions, with the researchers found that only 0.09% of ZEC transactions within a 30-day period made full use of the protocol’s privacy features. As a comparing, MWC is native Mimblewimble chain, with 100% privacy transactions.

Comes to NIT itself, MWC’s NIT design is just an optimisation for user experience on Mimblewimble, without any discount on privacy. MWC’s NIT will use the paper https://eprint.iacr.org/2020/1064.pdf, which is a quite elegant solution, since it also considers the address privacy, i.e. the Stealth Address concept which is used in Monero for years. In contrast, both LTC Mimblewimble extension and Tari script do not take into account for privacy address, the wallet address will be trackable in the chain public data.

About the payload cost for one-sided(non-interactive) transaction solution, Tari script document is not detailed on that, and it would be a little bit complex to discuss the script size since it's very flexible. So, let's only compare LTC LIP-004 and NIT here. In LIP-004, there could be 3 signatures in one typical 1 input 2 outputs transaction: 1st one in tx kernel, 2nd one in payment output (for sender signature), 3rd one for transaction input. A little bit complex and not so elegant, also the additional payload for that is much bigger, since each output needs:

1. Sender Public Key (ephemeral). (It could be the nonce R.) 
2. Receiver Public Key. (as wallet address?) 
3. Encrypted data for value & blinding factor, which at least needs 8+32=40 bytes 
4. Sender Signature. 64 bytes. Plus the Input signature (64 bytes) and the owner_offset (32 bytes).

So, a typical transaction with 1i2o in LTC LIP-004 would need 266 bytes additional payload. In comparing, NIT could only need 66 bytes (a R and a P') for each Output, plus Input signature (64 bytes). And 2 signatures instead of 3, simpler here.

#### Rollout/Deployment (HF2) 

The following rules will be enforced during rollout as part of HF2 -

__Assumptions:__

1. There is no any other hard fork before this date of NIT feature releasing.
2. Blocks at height < 768,000 (this number is to be discussed and modified) will have block version <= 2.

__Block Specific Rules:__

1. A block containing NIT(s) is only be valid if block version >= 3.
2. A block containing NIT(s) is only valid if all defined validations are passed.

__Transaction Specific Rules:__

1. A NIT transaction will not be accepted by the local txpool/stempool unless chain head version >= 3.
2. A NIT transaction will not be relayed or broadcast to other nodes unless chain head version >= 3.
3. A NIT transaction will not be accepted by the local txpool/stempool unless it passes all the validations.
4. A NIT transaction will not be relayed or broadcast to other nodes unless it passes all the validations.

#### Weights & Fees

To Be Defined.

## Drawbacks
[drawbacks]: #drawbacks

As described in §2.2.1 of NIT paper, the cut-through in same block and in txpool/stempool is frozen for NITs. The cut-through between the blocks is still feasible, which is great to reduce weight for non-archive nodes. 

## Rationale and alternatives
[rationale-and-alternatives]: #rationale-and-alternatives

Interactive transaction is indeed not the proper way in most of common use cases, and user experience is also one of the key factors for the global and common universal application. We believe NIT is the right direction, since the latest researches reserve the privacy characters very well.

The Tari script would like to import Bitcoin-style script into Mimblewimble, which is quite interesting and could also be an option as next step for MWC, but we need more information about that, since the current Tari implementation does not come to this part yet, and the related documents there seems inadequate for this part.

## References
[references]: #references

* [Mimblewimble Non-Interactive Transaction Scheme][1]
* [CryptoNote White Paper §4.3 Unlinkable Payments][2]
- [One-sided MW Transactions for LTC Extension Block][3]
- [Tari-specific Extensions to Mimblewimble][4]

[1]: https://eprint.iacr.org/2020/1064.pdf
[2]: https://decred.org/research/saberhagen2013.pdf
[3]: https://github.com/litecoin-project/lips/pull/13
[4]: https://rfc.tari.com/RFC-0201_TariScript.html
