# Recorded-history admission replay (RQ2)

- `artifacts/`: immutable content-addressed artifacts for the original Base Sepolia task (Intent, lifecycle model, policy, Action, Payment, Evidence), plus the separate offline replay artifacts.
- `results/55ddb203...json`: original interrupted creation journal, retained for forensic provenance; **not** the successful final experiment report.
- `recovery/55ddb203...json`: completed on-chain recovery and verifier results; includes task and transition transaction hashes.
- `results/71364a88...json`: separate, fully simulated/offline replay report.

The completed Base Sepolia experiment contains two structurally consistent recorded transitions. Admission replay rejects the second (index 1), because an equivalent service already succeeded. Both Payment references are synthetic, so settlement remains `unverified`. Read-only verification uses `scripts/verify_committed_task.py` with `--store experiments/admission_replay/artifacts`; see [instructions](../../docs/REPRODUCIBILITY.md#independent-admission-replay--published-on-chain-experiment).
