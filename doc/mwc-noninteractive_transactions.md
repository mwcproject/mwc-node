An MWC non-interactive transaction consists of:

* **A list of outputs: tuples of the form out = (Cˆ, πˆ, Rˆ, ρˆ, Pˆ), each implicitly associated to an output address (A, B), composed of:**
    + an ephemeral key Rˆ = ˆrG ∈ G, chosen by the sender, which defines two keys as:
    (ˆk, qˆ) := H(ˆrA,(A, B)) (note that kˆ and qˆ can be computed from the view key and Rˆ since rˆA = aRˆ)
    + a commitment Cˆ := vˆH + qˆG to the coin value vˆ, using randomness qˆ
    + a range proof πˆ proving knowledge of an opening (v, q) of Cˆ, with v ∈ [0, vmax]
    + a one-time output public key Pˆ ∈ G, computed from kˆ as Pˆ := Bˆ + kG (note that the spend key is required to compute log Pˆ)
    + a proof of possession ρˆ of Rˆ with tag Cˆ||πˆ||Pˆ (and possibly a time stamp)
* **A list of inputs of the form (P, D, ψ) where**
    + P ∈ G is the one-time public key of the transaction output being spent (each value P is only allowed once in the ledger);
    + D ∈ G is the one-time doubling key, chosen by the sender, that “doubles” P
    + ψ is a proof of possession of P and D with tag the transaction output being spent
* **The kernel, which is composed of:**
    + the supply s ∈ [0, vmax], indicating the amount of money created in the transaction
    + the fee f ∈ [0, vmax], indicating the fee paid for the current transaction
    + the offset t ∈ ℤ<sub>p</sub>
    + the excess E ∈ G, defined as the difference between the commitments in the outputs (including the fee) and the inputs (including the supply),
    shifted by the offset. If Ci is the i-th input commitment, that is, the value contained in the output in which Pi appears, then
        E := &sum;Cˆ + fH − &sum;C − sH − tG,
    which can be seen as E := E' −tG in terms of the *true excess* E' := &sum;Cˆ + fH − &sum;C − sH
    + a signature σ under E on the empty message ε
    + the stealth offset y ∈ ℤ<sub>p</sub>
    + the stealth excess X ∈ G, defined as the difference between the ephemeral keys Rˆi from the outputs and the one-time keys Pi from the inputs, shifted by the stealth offset y
        X := &sum;Rˆ − &sum;P − yG
    + a proof of possession σ of E and X (with empty tag ε)