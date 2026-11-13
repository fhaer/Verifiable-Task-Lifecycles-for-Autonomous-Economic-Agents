#!/usr/bin/env python3
"""Independent READ-ONLY verification for a newly committed policy-snapshot task."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from verifiable_task_lifecycles.artifact_store import ArtifactStore
from verifiable_task_lifecycles.committed_verifier import verify_committed_task
from verifiable_task_lifecycles.web3_task_reader import Web3TaskReader
from verifiable_task_lifecycles.settlement_audit import audit_committed_settlements


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc-url", required=True, help="RPC endpoint on the intended chain")
    parser.add_argument("--contract", required=True, help="LifecycleTracker contract address")
    parser.add_argument("--instance-id", required=True, help="committed task bytes32 ID")
    parser.add_argument("--store", required=True, help="directory containing hashed off-chain JSON artifacts")
    parser.add_argument("--chain-id", type=int, default=84532, help="expected chain ID (default Base Sepolia)")
    parser.add_argument("--settlement-asset", help="trusted ERC-20 contract (enables settlement audit)")
    parser.add_argument("--atomic-units-per-budget-unit", type=int,
                        help="trusted token atomic units per task budget unit")
    parser.add_argument("--min-confirmations", type=int, default=1,
                        help="required settlement confirmation depth")
    args = parser.parse_args()
    if bool(args.settlement_asset) != (args.atomic_units_per_budget_unit is not None):
        parser.error("--settlement-asset and --atomic-units-per-budget-unit must be provided together")
    try:
        reader = Web3TaskReader(
            rpc_url=args.rpc_url, contract_address=args.contract,
            expected_chain_id=args.chain_id,
        )
    except (ValueError, ImportError, OSError) as exc:
        print(json.dumps({"error": f"reader initialization failed: {exc}"}, indent=2))
        return 2

    report = verify_committed_task(
        instance_id=args.instance_id,
        store=ArtifactStore(args.store),
        ledger=reader,
    )
    details = None
    if args.settlement_asset:
        audit = audit_committed_settlements(
            instance_id=args.instance_id,
            ledger=reader,
            store=ArtifactStore(args.store),
            recorded_report=report,
            web3=reader.w3,
            asset=args.settlement_asset,
            atomic_units_per_budget_unit=args.atomic_units_per_budget_unit,
            network=f"eip155:{args.chain_id}",
            min_confirmations=args.min_confirmations,
        )
        report.settlement_check = audit.status
        details = audit.as_dict()
    output = report.as_dict()
    if details is not None:
        output["settlement_evidence"] = details
    print(json.dumps(output, indent=2))
    # Without optional audit, 0 still means only recorded-policy verification.
    # If explicitly requested, settlement verification must also pass.
    return 0 if (report.recorded_policy_verified and
                 (details is None or report.settlement_check == "pass")) else 1


if __name__ == "__main__":
    raise SystemExit(main())
