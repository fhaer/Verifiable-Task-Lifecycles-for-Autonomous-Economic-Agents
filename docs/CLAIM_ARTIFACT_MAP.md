# Claim-to-artifact map

| Paper claim/evaluation item | Reproducible evidence |
|---|---|
| RQ1/T1–T5: Controller admission | `experiments/controlled_cases/cases.json`; `tests/test_lifecycle.py` tests 01–05 |
| T6: Evidence modification detection | `tests/test_lifecycle.py` test 06; historical external artifacts in `experiments/external_interop/run.json` |
| Additional payment/evidence bindings and anti-reuse checks | `tests/test_lifecycle.py` tests 07–12 |
| Five controlled Base Sepolia runs; eight paid transitions; 18 lifecycle transactions | `experiments/live_base_sepolia/results/live_run_*.json`; `scripts/validate_results.py`; `scripts/summarize_live_runs.py` |
| RQ3: Historical gas, fees and latency | `experiments/live_base_sepolia/results/live_summary.json` and `.csv`, plus raw run receipts |
| Historical two-transition RQ2 verification | `experiments/independent_verification/result.json` — archived structural/receipt result, not new policy replay |
| **Independent recorded-policy replay (RQ2)** | `experiments/admission_replay/recovery/55ddb20339902e675e2a1258d80b995192aa04c4047bcf90ede62483e9d1813f.json`; committed artifacts in `experiments/admission_replay/artifacts/`; `scripts/verify_committed_task.py` |
| First structurally valid purchase passes replay; redundant second purchase fails | Same on-chain recovery report; `tests/test_adversarial_experiment.py`, `tests/test_committed_verifier.py` |
| Policy source and artifact commitments | `src/verifiable_task_lifecycles/policy_snapshot.py`, `canonical.py`, `task_creation.py`; `tests/test_policy_snapshot.py` |
| Historical external-service interoperability | `experiments/external_interop/run.json`, `final_verification.json`; `scripts/verify_external_artifacts.py` |
| **Independent live x402 payment validation** | `experiments/live_x402/first_payment.json`; trusted terms in `examples/live_sanctions_testnet.json`; `scripts/run_live_x402.py`; `scripts/verify_erc20_transfer.py` |
| Mismatch rejected before authorization | Test `tests/test_live_x402_experiment.py`; preserved live preflight negative-control result in payment journal |
| Receipt plus ERC-20 `Transfer` verification | `src/verifiable_task_lifecycles/payment_assurance.py`; `tests/test_payment_assurance.py`, `tests/test_settlement_audit.py` |
| Safe handling of uncertain settlement outcomes | `src/verifiable_task_lifecycles/x402_client.py`; `tests/test_x402_guard.py` |
| Deployed contract ABI and compatibility | `src/verifiable_task_lifecycles/deployed_contract_profile.py`; `tests/test_deployed_recovery.py`; `docs/PROVENANCE.md` |
| Trust boundaries and evaluation scope | `docs/TRUST_MODEL.md`; paper Sections III-D and VI |

The on-chain adversarial experiment uses **synthetic payments**; the genuine ERC-20 transfer was a **standalone** x402 test. These must not be reported as one end-to-end paid lifecycle experiment.
