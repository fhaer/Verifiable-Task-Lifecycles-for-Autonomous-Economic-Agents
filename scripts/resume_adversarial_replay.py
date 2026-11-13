#!/usr/bin/env python3
"""Recover and optionally finish the EXACT Step 4 instance already created.

Default: read-only reconciliation; no private key, no transactions, no new task.
Live continuation: --send AND --acknowledge-synthetic-payments, with a key.
The underlying Payment/Evidence records are synthetic; this is NOT an x402 test.
On unknown transaction status DO NOT rerun; inspect recovery report and chain.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from verifiable_task_lifecycles.adversarial_recovery import (
    RecoveryError, reconcile_recorded_prefix,
)
from verifiable_task_lifecycles.artifact_store import ArtifactStore
from verifiable_task_lifecycles.web3_task_reader import Web3TaskReader


def _save_exclusive(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def _update(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        with tmp.open("x", encoding="utf-8") as stream:
            json.dump(data, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--journal", required=True, type=Path, help="existing failed Step 4 journal; never modified")
    parser.add_argument("--creation-tx", required=True, help="original confirmed createInstance transaction hash")
    parser.add_argument("--store", required=True, help="existing Step 4 content-addressed artifacts")
    parser.add_argument("--rpc-url", default=os.environ.get("BASE_SEPOLIA_RPC_URL", "https://sepolia.base.org"))
    parser.add_argument("--send", action="store_true", help="submit ONLY missing transition commitments")
    parser.add_argument("--acknowledge-synthetic-payments", action="store_true")
    parser.add_argument("--key-env", default="EVM_PRIVATE_KEY")
    parser.add_argument("--output", type=Path, help="new recovery journal for --send; refuses overwrite")
    args = parser.parse_args()

    if args.send:
        if not args.acknowledge_synthetic_payments:
            parser.error("--send requires --acknowledge-synthetic-payments")
        if not os.environ.get(args.key_env):
            parser.error("--send requires private key in " + args.key_env)
    elif args.acknowledge_synthetic_payments:
        parser.error("acknowledgement is only meaningful with --send")
    try:
        journal = json.loads(args.journal.read_text(encoding="utf-8"))
        store = ArtifactStore(args.store)
        from web3 import Web3
        w3 = Web3(Web3.HTTPProvider(args.rpc_url))
        if int(w3.eth.chain_id) != 84532:
            raise RecoveryError("wrong network: recovery only supports Base Sepolia")
        contract_addr = journal["contract"]

        def fresh_reader():
            return Web3TaskReader(
                rpc_url=args.rpc_url, contract_address=contract_addr,
                expected_chain_id=84532,
            )

        existing = reconcile_recorded_prefix(
            journal=journal, creation_tx=args.creation_tx,
            store=store, ledger=fresh_reader(), w3=w3,
        )
        summary = {"mode": "read-only-recovery-check", "created_existing_instance": True,
                   "onchain_lifecycle_commitments": True, "submitted_transactions": 0,
                   **existing.as_dict()}
        if not args.send:
            print(json.dumps(summary, indent=2))
            return 0

        from verifiable_task_lifecycles.web3_experiment_recorder import Web3ExperimentRecorder
        recorder = Web3ExperimentRecorder(
            rpc_url=args.rpc_url, contract_address=contract_addr,
            private_key=os.environ[args.key_env], expected_chain_id=84532,
        )
        if recorder.contract_profile != "deployed-legacy":
            raise RecoveryError("refusing to resume against an unrecognized contract profile")
        if recorder.account.address.lower() != existing.creator.lower():
            raise RecoveryError("signing key is not the creator of the existing instance")

        path = args.output or (
            ROOT / "experiments" / "admission_replay" / "recovery"
            / (existing.instance_id.removeprefix("0x") + ".json")
        )
        run = {
            "schema": "admission-replay-recovery/v1",
            "mode": "onchain-ledger-with-simulated-payments",
            "creation_tx": args.creation_tx,
            "original_journal": str(args.journal),
            "instance_id": existing.instance_id,
            "contract": contract_addr,
            "actual_payments": False,
            "provider_attested": False,
            "settlement_check": "unverified",
            "initial_transition_count": existing.transition_count,
            "events": [],
            "phase": "ready-to-resume-existing-instance",
            "warning": "No actual x402 payments. Do not retry on uncertain transaction status.",
        }
        _save_exclusive(path, run)

        def event(kind: str, fields: dict) -> None:
            run["phase"] = kind
            run["events"].append({"event": kind, **fields})
            _update(path, run)

        try:
            for index in range(existing.transition_count, 2):
                # Independent readback, including prefix equality, BEFORE EVERY send.
                current = reconcile_recorded_prefix(
                    journal=journal, creation_tx=args.creation_tx,
                    store=store, ledger=fresh_reader(), w3=w3,
                )
                if current.transition_count != index:
                    raise RecoveryError("transition count changed during recovery; no transaction sent")
                record = journal["transitions"][index]
                event("before_record", {"index": index, "commitments": record})
                txid = recorder.record_transition(
                    instance_id=existing.instance_id,
                    expected_index=index,
                    action_hash=record["action_hash"],
                    payment_hash=record["payment_hash"],
                    evidence_hash=record["evidence_hash"],
                )
                event("recorded", {"index": index, "tx": txid})
                verified = reconcile_recorded_prefix(
                    journal=journal, creation_tx=args.creation_tx,
                    store=store, ledger=fresh_reader(), w3=w3,
                )
                if verified.transition_count != index + 1:
                    raise RecoveryError("record count did not advance by one")
                event("verified", {"index": index, "result": verified.report.as_dict()})

            final = reconcile_recorded_prefix(
                journal=journal, creation_tx=args.creation_tx,
                store=store, ledger=fresh_reader(), w3=w3,
            )
            if final.transition_count != 2:
                raise RecoveryError("recorded history is not complete")
            run.update({"phase": "finished", "transition_count": 2,
                        "final_verification": final.report.as_dict(),
                        "claim": "On-chain structural pass, admission replay fail at transition 1; payments synthetic"})
            _update(path, run)
            print(json.dumps({"report": str(path), **run}, indent=2))
            return 0
        except Exception as exc:
            run["phase"] = "error-reconcile-before-retry"
            run["error"] = f"{type(exc).__name__}: {exc}"
            _update(path, run)
            raise
    except Exception as exc:
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}",
                          "instruction": "Do NOT automatically retry a live step. Inspect the chain and journal."}, indent=2),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
