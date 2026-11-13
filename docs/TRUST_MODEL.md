# Trust and assurance boundaries

The prototype separates lifecycle **structural consistency**, **recorded-policy admission replay**, and **settlement verification**.

* Ledger commitments and off-chain artifact hashes support recomputation of committed identifiers, object bindings and order.
* The verifier replays `enabled_M`, `auth_I` and `Π` against the committed Intent/policy and preceding **recorded** outcomes using pinned evaluator semantics. It does not trust the controller's original permit/deny decision.
* The controller constructs Evidence. Neither the committed Intent nor service Evidence carries independent principal/provider signatures in the current workflow. Hence recorded-policy checks do not authenticate external events or establish absence of omitted actions.
* A successful transaction receipt alone is not sufficient ERC-20 transfer evidence. The optional payment audit checks the expected token contract, payer, recipient, atomic amount and confirmation depth against an observed `Transfer` event. Token/chain/price-unit settings must be independently trusted; they are not all committed by the original task policy snapshot.
* The payment client rejects mismatching x402 challenges before signing, and does not perform application-level automatic retries after unknown settlement outcomes. Crash-safe payment reconciliation, provider-result attestations, and exactly-once execution are not implemented.

The original five-run historical dataset, the on-chain admission-replay counterexample with **synthetic** payments, and the independent live x402 transfer test are distinct experiments.
