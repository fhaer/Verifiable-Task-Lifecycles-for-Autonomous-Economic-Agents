#!/usr/bin/env python3
"""Step 4: replay-valid prefix then policy-invalid on-chain history (simulated payments).

Default is SAFE, OFFLINE, and makes no RPC calls. Live lifecycle writes require
BOTH --send and --acknowledge-synthetic-payments. They spend testnet ETH on
contract calls but NEVER execute an x402 token transfer or paid service call.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from verifiable_task_lifecycles.adversarial_experiment import (
    prepare_adversarial_experiment, run_offline_experiment,
    run_onchain_experiment,
)
from verifiable_task_lifecycles.artifact_store import ArtifactStore
from verifiable_task_lifecycles.model import Intent
from verifiable_task_lifecycles.policy import CatalogEntry, PolicyEvaluator, TrustedCatalog


def _write_json_atomically(path: Path, data: dict) -> None:
    """Keep a durable journal even when a live transaction has uncertain status."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    try:
        with temp.open("x", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temp.replace(path)
    finally:
        if temp.exists():
            temp.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=str(ROOT / "examples" / "admission_replay_experiment.json"))
    parser.add_argument("--store", default="./task_artifacts")
    parser.add_argument("--report", help="JSON output; must not exist before running")
    parser.add_argument("--send", action="store_true", help="explicitly submit 3 Base Sepolia lifecycle transactions")
    parser.add_argument(
        "--acknowledge-synthetic-payments", action="store_true",
        help="required with --send: Payment/Evidence in this experiment are simulated, NOT real x402 settlements",
    )
    parser.add_argument("--rpc-url", default=os.environ.get("BASE_SEPOLIA_RPC_URL"))
    parser.add_argument("--contract", default=os.environ.get("LIFECYCLE_CONTRACT_ADDRESS"))
    parser.add_argument("--key-env", default="EVM_PRIVATE_KEY")
    args = parser.parse_args()

    if args.send:
        if not args.acknowledge_synthetic_payments:
            parser.error("--send requires --acknowledge-synthetic-payments")
        if not args.rpc_url or not args.contract or not os.environ.get(args.key_env):
            parser.error(
                "--send requires --rpc-url, --contract and a private key in the "
                + args.key_env + " environment variable"
            )
    elif args.acknowledge_synthetic_payments:
        parser.error("--acknowledge-synthetic-payments is only meaningful with --send")

    raw = json.loads(Path(args.config).read_text(encoding="utf-8"))
    if set(raw) != {"intent", "catalog", "first_service", "second_service"}:
        parser.error("config must include intent, catalog, first_service, second_service")
    iraw = raw["intent"]
    intent = Intent(
        goal=iraw["goal"], budget=iraw["budget"],
        allowed_services=tuple(iraw["allowed_services"]),
        allowed_providers=tuple(iraw["allowed_providers"]),
    )
    evaluator = PolicyEvaluator(TrustedCatalog([CatalogEntry(**item) for item in raw["catalog"]]))
    store = ArtifactStore(args.store)
    experiment = prepare_adversarial_experiment(
        intent=intent, evaluator=evaluator, store=store,
        first_service=raw["first_service"], second_service=raw["second_service"],
    )

    path = Path(args.report) if args.report else (
        ROOT / "experiments" / "admission_replay" / "results"
        / (experiment.prepared.instance_id + ".json")
    )
    if path.exists():
        parser.error(f"report already exists, refusing to overwrite: {path}")

    if not args.send:
        outcome = run_offline_experiment(experiment=experiment, store=store)
        _write_json_atomically(path, outcome)
        print(json.dumps({"report": str(path), **outcome}, indent=2))
        return 0

    # LIVE testnet sends: creation + two recordTransition calls; no x402 payments.
    # Store the intent/commitments and the last known phase BEFORE any tx.
    journal = {
        "schema": "admission-replay-experiment-journal/v1",
        "phase": "prepared-not-broadcast",
        "mode": "onchain-ledger-with-simulated-payments",
        "onchain_lifecycle_commitments": False,
        "actual_payments": False,
        "settlement_check": "unverified",
        "instance_id": "0x" + experiment.prepared.instance_id,
        "intent_hash": "0x" + experiment.prepared.intent_id,
        "policy_hash": "0x" + experiment.prepared.policy_id,
        "model_hash": "0x" + experiment.prepared.model_id,
        "contract": args.contract,
        "chain_id": 84532,
        "transitions": [t.as_dict() for t in experiment.transitions],
        "events": [],
        "warning": "Synthetic settlement refs are NOT real payments. Inspect chain before retrying interrupted sends.",
    }
    _write_json_atomically(path, journal)

    def event(name: str, info: dict) -> None:
        journal["phase"] = name
        journal["events"].append({"event": name, **info})
        _write_json_atomically(path, journal)

    try:
        from verifiable_task_lifecycles.web3_experiment_recorder import Web3ExperimentRecorder
        from verifiable_task_lifecycles.web3_task_reader import Web3TaskReader

        recorder = Web3ExperimentRecorder(
            rpc_url=args.rpc_url, contract_address=args.contract,
            private_key=os.environ[args.key_env], expected_chain_id=84532,
        )
        def fresh_reader():
            return Web3TaskReader(
                rpc_url=args.rpc_url, contract_address=args.contract,
                expected_chain_id=84532,
            )

        result = run_onchain_experiment(
            experiment=experiment, intent=intent, store=store,
            recorder=recorder, reader_factory=fresh_reader, on_event=event,
        )
        result["chain_id"] = 84532
        result["contract"] = args.contract
        result["onchain_lifecycle_commitments"] = True
        result["journal_events"] = journal["events"]
        _write_json_atomically(path, result)
        print(json.dumps({"report": str(path), **result}, indent=2))
        return 0
    except Exception as exc:
        journal["phase"] = "error-reconcile-before-retry"
        journal["error"] = f"{type(exc).__name__}: {exc}"
        _write_json_atomically(path, journal)
        print(json.dumps({"report": str(path), "error": journal["error"],
            "instruction": "Inspect the journal and on-chain state BEFORE running another live experiment."}, indent=2), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
