# Verifiable Task Lifecycles for Autonomous Economic Agents Using Distributed Ledgers

Reference implementation and reproducibility material for the paper *Verifiable Task Lifecycles for Autonomous Economic Agents Using Distributed Ledgers*.

A delegated economic task is represented as a persistent lifecycle. The controller admits runtime-selected paid actions against task constraints, and each recorded transition binds an Action, Payment, and Evidence to a committed Intent. Complete objects are stored off-chain. Their content commitments, order, and lifecycle state are recorded on a distributed ledger.

An independent verifier reconstructs the recorded history and checks structural consistency against the committed policy as well as admission in case of replays based on recorded outcomes. A separate payment audit can validate selected x402 terms before signing and verify observed ERC-20 transfer properties. 

## Quick start

Requires Python 3.13+. The deterministic test suite needs no wallet, RPC, paid service, or optional live dependencies.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
PYTHONPATH=src python -m unittest discover -s tests -v
```

Expected: 149 tests pass. To install RPC, x402, and provider dependencies for optional live checks:

```bash
python -m pip install -e '.[live]'
```

See [Reproducibility](docs/REPRODUCIBILITY.md) for the complete command reference and safe live-test instructions.

## Results and evidence

| Experiment | Preserved material | What it establishes |
|---|---|---|
| RQ1: Controlled admission and integrity cases | `experiments/controlled_cases/`, `tests/test_lifecycle.py` | T1–T6 and additional deterministic checks |
| RQ2: Historical independent verification | `experiments/independent_verification/result.json` | Archived two-transition structural/receipt verification; original bundle not retained |
| RQ2: On-chain adversarial admission replay | `experiments/admission_replay/` | Two Base Sepolia transitions are structurally consistent; replay rejects the second as policy-inadmissible. Payments simulated |
| RQ3: Ledger overhead | `experiments/live_base_sepolia/results/` | Five controlled runs, eight paid transitions, 18 lifecycle transactions |
| Historical external-provider interoperability | `experiments/external_interop/` | Archived independently operated service interaction and artifact check |
| Standalone live x402 payment validation | `experiments/live_x402/first_payment.json` | Exact challenge matched; a local price-mismatch control was rejected before signing; an independent ERC-20 transfer check passed |

The adversarial history and the live x402 transfer are separate experiments. The live payment was not committed as a settlement of the adversarial task.

### Published Base Sepolia deployment

- Chain: Base Sepolia (`eip155:84532`)
- Lifecycle contract: `0xE27e67da9D39aF51D778648E50EE2182C5B2D680`
- Adversarial task instance: `0x55ddb20339902e675e2a1258d80b995192aa04c4047bcf90ede62483e9d1813f`
- Adversarial task creation: `0x2e382c00af0d884cf815587c9a91989101e54cbf4fa08663e7163bf89278ed35`
- Recorded transitions: `0xcf5ebed468a2c15b9d22f1cb65216cb16aa06d4609db919227e5d877c03790d5` and `0x8410ae1c60cc6a876810673b2324099cbef032033a8c5e7dbc5570c8d76146be`
- Independently checked x402 settlement (separate experiment): `0x2024b3394feec473355f55a08ed318a20b107a8387216e9d42b3a749508f575c`

Contract compatibility: the reference Solidity source and the archived deployed contract have different ABIs. The Python reader/recorder selects the pinned deployed interface after checking its runtime bytecode hash. See [Provenance](docs/PROVENANCE.md) and [contracts](contracts/README.md).

## Reproduce archived evaluations (offline)

```bash
python scripts/validate_results.py
python scripts/summarize_live_runs.py
python scripts/verify_external_artifacts.py
```

The first script verifies the archived five-run summary. The external-provider command validates historical artifact commitments and bindings. 

## Verify the adversarial task (read-only Base Sepolia RPC)

With optional live dependencies installed:

```bash
PYTHONPATH=src python scripts/verify_committed_task.py \
  --rpc-url https://sepolia.base.org \
  --contract 0xE27e67da9D39aF51D778648E50EE2182C5B2D680 \
  --instance-id 0x55ddb20339902e675e2a1258d80b995192aa04c4047bcf90ede62483e9d1813f \
  --store experiments/admission_replay/artifacts
```

Expected: `structural_consistency=pass`, `admission_replay=fail`, `denied_transition=1`, `settlement_check=unverified`. Exit code 1 is expected: the recorded second transition intentionally violates admission policy.

## Test x402 terms without paying

```bash
PYTHONPATH=src python scripts/run_live_x402.py \
  --config examples/live_sanctions_testnet.json
```

The default mode performs an unauthenticated 402 challenge preflight and a local price-mismatch negative control, without signing or paying. An explicitly acknowledged paid run is optional and must use a fresh journal. See also: [live-payment instructions](docs/REPRODUCIBILITY.md#standalone-x402-payment-test).

## Layout

```text
contracts/                        Reference Solidity contract and Foundry tests
docs/                             Reproducibility, formal model, provenance, trust boundaries
examples/                         Example Intent/catalog and pinned live-service configuration
experiments/                      Archived results and content-addressed evidence
scripts/                          Verification, experiment, and optional diagnostic CLIs
services/                         Controlled service implementation
src/verifiable_task_lifecycles/   Python implementation
tests/                            149 deterministic unit tests
```

Archived reports are preserved as evidence. For a paper-claim-to-evidence index, see [Claim-to-artifact map](docs/CLAIM_ARTIFACT_MAP.md).
