# Exchange integration recommendations

## Overview

Use **Slatepack for both deposits and withdrawals**, with **1,440 confirmations
before crediting a deposit**. Use the maintained `mwc-wallet` with a synchronized
`mwc-node`. Enable late locking for withdrawals that wait for a customer's
Slatepack response, and manage change outputs to keep enough spendable outputs
available for subsequent withdrawals.

The software is distributed under the Apache License without warranty. Test the
complete deposit, withdrawal, retry and recovery workflows before enabling them
for customers.

## Software and integration assistance

- [mwc-node](https://github.com/mwcproject/mwc-node) validates the chain and
  provides the node APIs. See [Build and run](build.md) and
  [Chain synchronization](chain/chain_sync.md).
- [mwc-wallet](https://github.com/mwcproject/mwc-wallet) provides the wallet CLI,
  owner/foreign APIs and Slatepack processing for exchange integration.

## Slatepack deposits and withdrawals

A Slatepack carries the transaction data that sender and recipient exchange to
construct and sign a payment. Customers can copy and paste its text or upload
and download it as a file. Each party processes the message in their own wallet
and returns the response through the exchange website.

Use HTTPS to protect customer sessions and Slatepack uploads.

Prefer encrypted Slatepacks using the recipient's MWC Tor/Ed25519 address.
That address supplies the encryption key. Specify the recipient address when
creating the Slatepack to enable encryption.
See the wallet's
[Slatepack format guide](https://github.com/mwcproject/mwc-wallet/blob/master/doc/slatepack_data_format.md).

### Deposits

1. Show the exchange's Slatepack recipient address in the authenticated
   customer's deposit page. Associate each deposit request with that customer.
2. The customer creates a send Slatepack in their wallet and submits it to the
   exchange. The exchange receives it with `mwc-wallet`, records the slate ID,
   amount and receiving output commitments, and returns the response Slatepack.
3. The customer finalizes the response in their wallet and broadcasts the
   transaction for inclusion in the chain.
4. The exchange refreshes its wallet against its node, validates the deposit and
   waits for 1,440 confirmations before crediting it. Handle repeated uploads
   and polling results idempotently, crediting each deposit exactly once.

Keep the association between the authenticated customer and each deposit
request in the exchange database.

### Withdrawals

1. Reserve the withdrawal amount in the exchange's customer ledger and obtain
   the customer's Slatepack recipient address.
2. Create a send Slatepack with late locking enabled and give it to the customer.
   Persist the wallet transaction context and the link between the withdrawal
   request and slate ID.
3. The customer receives the Slatepack in their wallet and returns the response.
   Match it to the pending withdrawal and let `mwc-wallet` validate and finalize
   it. The exchange controls finalization in this workflow.
4. Broadcast the finalized transaction promptly and track its confirmation.
   Distinguish waiting for a response, finalized, broadcast and confirmed states
   in the customer interface. Mark a withdrawal confirmed after validating its
   inclusion in the chain.

The CLI `finalize` command posts by default unless `--nopost` is supplied.
Integrations using the wallet owner API must perform the corresponding
`post_tx` operation after `finalize_tx` to broadcast the transaction.
On a posting failure, retain and retry the same finalized transaction.

### Late locking (`late_lock`)

The implementation calls this option **`late_lock`** in `init_send_tx` arguments
and **`--late-lock`** (or `-l`) in the CLI.
It requires compact slates; `--method slatepack` selects the supported format.

Late locking keeps inputs available while waiting for the customer's response.
It estimates the transaction at creation and saves the signing context and
selection policy. It selects the actual inputs and locks them when the returned
response is finalized.

Reserve each pending withdrawal in the customer ledger and maintain sufficient
spendable wallet funds to cover pending requests. Finalization can fail if the
required inputs are no longer available or a new selection exceeds the fee
fixed by the initial Slatepack. Record that failure and keep the withdrawal
pending for recovery or cancellation. Keep its wallet context until completion
or deliberate cancellation.

For example, create an encrypted 10 MWC withdrawal using mature inputs and
request four change outputs:

```sh
mwc-wallet send --method slatepack --late-lock --min_conf 1440 \
  --change_outputs 4 --slatepack_recipient '<customer-address>' \
  --dest withdrawal.slatepack 10
```

Here `--dest` is the output filename; the customer's encryption address belongs
in `--slatepack_recipient`. After saving the customer's returned response as
`withdrawal.response.slatepack`, finalize and broadcast it:

```sh
mwc-wallet finalize --file withdrawal.response.slatepack
```

## Controlling the number of wallet outputs

An output is spent as a whole. The amount left after paying the customer and
transaction fee returns to the exchange as **change**. Separate spendable outputs
let the wallet fund multiple withdrawals without waiting for a single large
output's change to become available again.

Use `send --change_outputs N` (or `-o N`), or `num_change_outputs: N` in owner
API `init_send_tx`, to split that change. The default is one. This controls the
number of change outputs returning to the sender for that transaction.

For an external withdrawal, once confirmed:

```text
wallet output count after = count before - inputs spent + change outputs created
```

For example, consuming one wallet output and creating four change outputs
increases the wallet's unspent-output count by three. Consuming six inputs and
creating one change output reduces it by five. Newly created change still has
to satisfy the selected confirmation policy before it can fund another send.

- Increase change outputs when the withdrawal wallet needs more independently
  spendable pieces. Consider both their number and their values relative to
  typical withdrawal amounts.
- Reduce change outputs and consolidate inputs when the wallet has too many
  small outputs. `--selection all` selects more eligible inputs within the
  wallet's limits; the owner API equivalent is
  `selection_strategy_is_use_all: true`. Select the strategy explicitly in API
  integrations.
- Allow for fees and transaction/Slatepack size limits. More change outputs add
  transaction data and can increase the required fee. An excessive split can
  fail size checks.

The requested count is a target. The wallet creates change outputs when the
selected inputs exceed the payment plus fee. If splitting would produce portions
smaller than 0.1 MWC, the wallet reduces the count; it can still return a single
smaller change output. Request at least one change output when the selected
inputs leave change. The rounding remainder is included in the final change
output.

### Separate confirmation thresholds for change

Change-output **count** and change-output **confirmations** are separate controls.
An exchange can require 1,440 confirmations for incoming funds while allowing
its own confirmed change to be reused sooner:

| Policy | CLI `send` option | Owner API `init_send_tx` field |
| --- | --- | --- |
| Ordinary input confirmations | `--min_conf 1440` | `minimum_confirmations: 1440` |
| Enable a separate threshold for change | `--exclude_change_outputs` | `exclude_change_outputs: true` |
| Change confirmations, for example one | `--minimum_confirmations_change_outputs 1` | `minimum_confirmations_change_outputs: 1` |
| Requested change-output count, for example four | `--change_outputs 4` | `num_change_outputs: 4` |

With `exclude_change_outputs` enabled, the wallet applies
`minimum_confirmations_change_outputs` to recognized change and the ordinary
confirmation threshold to other inputs. It identifies change using its
confirmed outgoing transaction records. Inputs must also be unlocked, unspent
and mature.

Keep the deposit crediting threshold at 1,440 confirmations and account for
reorganizations affecting the change's ancestor transaction. See
[change-output confirmation settings](https://github.com/mwcproject/mwc-wallet/blob/master/doc/change_outputs.md)
for the option semantics; use the exchange thresholds above.

## Deposit validation and confirmations

Require **at least 1,440 confirmations before crediting a deposit**. At the
one-minute target block interval this is approximately 24 hours. Determine
confirmations from block heights. For an output included at height
`h` on the current chain and a validated body tip at height `H`:

```text
confirmations = H - h + 1
```

An unconfirmed or reverted output has zero confirmations. Use the node's
validated body chain height for `H`.

Before crediting:

1. Verify that the exchange's node is synchronized and following the intended
   network. Refresh the wallet against that node. When the wallet API returns a
   validation flag, require it to be true; a successful call can otherwise
   return cached data after an unsuccessful refresh.
2. Match the confirmed payment to the recorded customer, slate ID, amount and
   output commitments. Compute confirmations using current chain data and
   repeat the check if a reorganization changes that data during processing.
3. Before sweeping or otherwise spending a deposit's outputs, independently
   check their presence on the exchange's node and their confirmation heights.
4. Record the credit exactly once in the exchange ledger, together with the
   evidence used to validate it. Continue monitoring for reorganizations.

For an unspent deposit output, the node's v2 foreign API supports this lookup:

```sh
curl --user 'mwcmain:<foreign-api-secret>' \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"get_outputs","params":[["<output-commitment>"],false,false]}' \
  http://127.0.0.1:3413/v2/foreign
```

Use the exchange's node address and foreign API credentials. Check for JSON-RPC
and `result.Err` errors before reading a successful `result.Ok`. Require the
expected commitment with `spent: false` and verify
its `block_height`. The wallet's `txs -i <tx_index>` output and owner API output
queries can identify the receiving commitments.

This commitment lookup returns currently unspent outputs. After spending or
sweeping an output, track it through the recorded spending transaction.
Preserve both deposit and spending-transaction records and reconcile them
against the current chain. API details are in [HTTP APIs](api/api.md).

### Reorganizations and double-spend risk

The current wallet refresh checks chain history and reconciles outputs and
transactions after a reorganization. Use that refresh and the node checks above
for routine deposit validation.

A competing higher-work chain, including one produced by withheld blocks, can
replace previously accepted history. Apply the confirmation threshold and
monitor reorganizations throughout the deposit lifecycle. See
[chain synchronization and forks](chain/chain_sync.md#forks-failed-suppliers-and-recovery).

If a credited deposit is reverted, suspend further spending of the affected
credit and reconcile the exchange ledger. Pause deposit crediting when the
node or wallet cannot establish current chain state.

## Sweeping deposits and managing reserves

An exchange may separate its deposit wallet, withdrawal wallet and cold storage.
Validate and credit matured deposits before sweeping their outputs, and transfer
funds periodically according to withdrawal demand and cold-storage policy.
Slatepack can be used for these transfers as well.

Use `--min_conf 1440` or a stricter threshold for ordinary inputs when sweeping.
`send` with a numeric amount transfers that amount. To sweep, use the CLI amount
`max`, which requests the available amount
under the selected policy and includes the fee in that amount. The recipient
receives the amount after the fee, and wallet/input-size limits still apply.

Allow for the destination outputs' confirmations when replenishing a separate
withdrawal wallet. Apply the incoming-output confirmation threshold there.
Keep enough spendable withdrawal outputs available while replacements
confirm. A single-wallet integration can instead use the separate change
confirmation threshold described above while retaining the same deposit
crediting policy.
