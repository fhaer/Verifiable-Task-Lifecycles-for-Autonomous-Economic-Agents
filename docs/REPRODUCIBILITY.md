# Reproducibility and execution guide

Run commands from the repository root. The project uses Python 3.13 or newer. Historical results are stored under `experiments/`; **do not overwrite them** with new observations.

## Install and test (offline)

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
PYTHONPATH=src python -m unittest discover -s tests -v
```

Expected: **149 passing tests** (standard library, mocked transports, no wallet, no network). Run all archived data checks:

```bash
python scripts/validate_results.py
python scripts/summarize_live_runs.py
python scripts/verify_external_artifacts.py
```

The controlled dataset contains five live Base Sepolia tasks, eight paid transitions, 18 lifecycle transactions, and 1,890,170 summed gas units. The historical external-provider artifact checker reports `verified=true` for the originally archived commitments and bindings; this is not retroactive policy replay or ERC-20 transfer verification. Original experiment timing cannot be reproduced by replaying JSON files.

## Offline task preparation

```bash
PYTHONPATH=src python scripts/create_task_instance.py \
  --config examples/task_creation_example.json \
  --store ./task_artifacts
```

Produces source-pinned, content-addressed Intent, lifecycle-model and policy artifacts; no on-chain task exists until explicitly registered. The example catalog contains dummy/local terms, not a production authorization. New task creation supports `--send` and requires a funded testnet wallet (`EVM_PRIVATE_KEY`), Base Sepolia RPC, and the intended contract address. Registration consumes gas. The operator must pin authorized task constraints and a trusted catalog before doing so. Treat uncertain transaction statuses as **reconciliation-needed**, never as permission to resubmit.

## Independent admission replay — published on-chain experiment

**Read-only** Base Sepolia verification of the committed adversarial task:

```bash
python -m pip install -e '.[live]'
PYTHONPATH=src python scripts/verify_committed_task.py \
  --rpc-url https://sepolia.base.org \
  --contract 0xE27e67da9D39aF51D778648E50EE2182C5B2D680 \
  --instance-id 0x55ddb20339902e675e2a1258d80b995192aa04c4047bcf90ede62483e9d1813f \
  --store experiments/admission_replay/artifacts
```

Expected: `structural_consistency=pass`, `admission_replay=fail`, `denied_transition=1`, `settlement_check=unverified`. The process exits **1 intentionally**, because the verifier detected an inadmissible second transition. Its content hashes are reconstructed from the original artifact JSONs in `experiments/admission_replay/artifacts/`. The on-chain task remains real, but both Payment references are **synthetic** (`SIMULATED-NO-SETTLEMENT`).

Re-run the safe *offline simulation* with new temporary artifacts/report:

```bash
PYTHONPATH=src python scripts/run_adversarial_replay.py \
  --config examples/admission_replay_experiment.json \
  --store ./task_artifacts \
  --report ./task_artifacts/offline_admission_replay.json
```

The on-chain history was originally created in an interrupted transaction and recovered safely. The original journal is under `experiments/admission_replay/results/`, and the completed recovery report under `experiments/admission_replay/recovery/`. A read-only check of that exact creation and prefix is available with `scripts/resume_adversarial_replay.py` and the original journal; consult `python scripts/resume_adversarial_replay.py --help`. **Do not run any of the `--send` modes to reproduce the existing result.** Any new live lifecycle experiment consumes Base Sepolia ETH and must use new IDs and paths.

## Standalone x402 payment test

The *separate* archived payment journal is `experiments/live_x402/first_payment.json`. The tested service requires `exact`, `eip155:84532`, the Circle test-USDC token `0x036CbD53842c5426634e7929541eC2318f3dCF7e`, the configured recipient `0xb3e7993ed2fc2c79fff220620240f298bba9bf5b`, and 10,000 atomic units (0.01 test USDC). These are **pinned trusted terms** from `examples/live_sanctions_testnet.json`; do not overwrite them from an HTTP challenge.

Read-only challenge preflight (no private key):

```bash
PYTHONPATH=src python scripts/run_live_x402.py \
  --config examples/live_sanctions_testnet.json
```

The script expects a reachable x402 v2 `402` response with at least one exact matching offer. A one-atomic-unit **local quote perturbation** is rejected before signing. A mismatch, malformed challenge, or unavailable service blocks payment; preflight behavior can change as the provider changes.

The recorded live payment was `0x2024b3394feec473355f55a08ed318a20b107a8387216e9d42b3a749508f575c` at Base Sepolia block 58,334,968. Verify the observed transfer independently, read-only:

```bash
PYTHONPATH=src python scripts/verify_erc20_transfer.py \
  --rpc-url https://sepolia.base.org \
  --tx 0x2024b3394feec473355f55a08ed318a20b107a8387216e9d42b3a749508f575c \
  --network eip155:84532 \
  --asset 0x036CbD53842c5426634e7929541eC2318f3dCF7e \
  --payer 0xF482471FE90aC83376554054c039F188CB6CFA87 \
  --recipient 0xb3e7993ed2fc2c79fff220620240f298bba9bf5b \
  --amount-atomic 10000 \
  --min-confirmations 3
```

Expected: `status=pass` with one matching ERC-20 `Transfer`. This validates the observed on-chain token/addresses/amount, **not** authenticated provider output or a lifecycle-linked settlement.

**Optional new paid request:** Only after successful preflight and independent review of the trusted catalog, a dedicated Base Sepolia test wallet with test USDC can run:

```bash
PYTHONPATH=src python scripts/run_live_x402.py \
  --config examples/live_sanctions_testnet.json \
  --rpc-url https://sepolia.base.org \
  --send --acknowledge-one-testnet-payment \
  --journal ./task_artifacts/new_live_payment.json
```

This performs one paid HTTP request via the x402 SDK and may transfer 0.01 **test** USDC. Set `EVM_PRIVATE_KEY` privately in your environment; never commit or share it. The runner creates an exclusive journal before authorizing payment and does **not** retry an uncertain settlement. Do not rerun after a timeout or service failure without first reconciling the transaction and journal. Crash-safe exactly-once payment is not implemented.

## Other verification modes

For new tasks with actual committed ERC-20 payments, `scripts/verify_committed_task.py` additionally supports `--settlement-asset` and `--atomic-units-per-budget-unit` provided from independent trusted configuration. These parameters enable an optional settlement audit separate from admission replay. The historical synthetic-payment task cannot pass such an audit.

The historical external-provider *receipt-only* checker remains `scripts/verify_settlement_receipts.py`. It confirms existence and successful receipt status, **not** a matching token transfer. The independent transfer checker is `scripts/verify_erc20_transfer.py`.

## Deployment, environment and provenance

The checked-in Solidity source is a *reference contract*, while the archived Base Sepolia deployment has a distinct ABI. The pinned runtime bytecode and supported selectors are documented in [Provenance](PROVENANCE.md). The corresponding Python reader and recorder choose the deployed-compatible interface only after checking its code hash. For optional contract tests: install Foundry and run `forge test` inside `contracts/`.

`requirements.txt` and `pyproject.toml` pin the live Python dependencies; the archived execution environment is recorded under `experiments/environment/`. `.env.example` contains public placeholders only and can be copied locally, but private keys and API tokens should be provided securely and excluded from version control. For the trust model, see [Trust boundaries](TRUST_MODEL.md). For evaluation evidence, see [Claim-to-artifact map](CLAIM_ARTIFACT_MAP.md).
