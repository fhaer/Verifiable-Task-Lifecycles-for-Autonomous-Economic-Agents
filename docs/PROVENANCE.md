# Evidence provenance and deployed contract compatibility

The archived material and the current reference implementation serve different purposes. Preserve the historical JSON results without rewriting them as new verification outputs.

## Archived controlled experiments

`experiments/live_base_sepolia/results/` contains five Base Sepolia controlled workflow runs (eight paid transitions and 18 lifecycle transactions). `experiments/independent_verification/result.json` is a historical two-transition structural/receipt verification report; its full exported artifact bundle was not retained, so it must not be presented as a fresh policy-admission replay. `experiments/external_interop/` retains a separate historical external-provider experiment. Receipt success in these records is not equivalent to a verified ERC-20 transfer.

## Recorded-history admission replay

`experiments/admission_replay/recovery/55ddb20339902e675e2a1258d80b995192aa04c4047bcf90ede62483e9d1813f.json` is the **actual Base Sepolia recovery experiment report**. The instance creation and two transition transactions are linked in that report. `experiments/admission_replay/artifacts/` preserves the content-addressed Intent, model, policy, Action, Payment, and Evidence objects for the experiment. `experiments/admission_replay/results/` retains the initial journal and a separate offline-simulation result. Both recorded transitions are structurally consistent; the second fails admission replay against the preceding recorded outcome. Payment references are synthetic; settlement remains unverified.

## Standalone live payment validation

`experiments/live_x402/first_payment.json` contains an observed standalone x402 v2 payment and independent ERC-20 transfer check. Transaction `0x2024b3394feec473355f55a08ed318a20b107a8387216e9d42b3a749508f575c` on Base Sepolia transferred 10,000 atomic units of test USDC according to the preserved verifier output. This was a **separate experiment**, not a settlement tied to the adversarial lifecycle. The price-mismatch negative control used a locally altered offer and caused no signing or payment.

## Contract API compatibility

The deployed paper contract at `0xE27e67da9D39aF51D778648E50EE2182C5B2D680` (Base Sepolia, chain 84532) has runtime-bytecode Keccak-256 `0x48eae3831745a93d12578aeafb60bdde0e9c62f76ec54cd5a45f526679be71e5`. It uses public getters `instances(bytes32)` and `transitions(bytes32,uint64)` and the deployed five-argument `recordTransition(bytes32,bytes32,bytes32,bytes32,uint8)` signature. The checked-in `contracts/src/LifecycleTracker.sol` is a **reference implementation with a different ABI** (private mappings, `getInstance`/`getTransition`, six-argument transition recording). The historical deployment binary/build metadata is not included; do **not** claim a byte-for-byte reproduction of that deployment from the checked-in Solidity source. `deployed_contract_profile.py` selects the pinned ABI after checking the deployed runtime bytecode hash.

## Reproducibility scope

Stored reports, public transaction IDs and off-chain artifacts can be independently inspected. New tests or live requests are not equivalent to reproducing historical timing measurements. A recorded-policy replay proves admissibility of a *recorded* history under the encoded policy, not completeness of actual service execution or signed principal/provider intent. See [Reproducibility](REPRODUCIBILITY.md) and [Trust boundaries](TRUST_MODEL.md).
