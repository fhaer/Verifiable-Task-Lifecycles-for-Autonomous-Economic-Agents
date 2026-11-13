#!/usr/bin/env python3
"""Prepare task/policy artifacts; optionally register NEW task on Base Sepolia.

Offline mode is the default. Only --send signs or broadcasts a transaction.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from verifiable_task_lifecycles.artifact_store import ArtifactStore
from verifiable_task_lifecycles.model import Intent
from verifiable_task_lifecycles.policy import CatalogEntry, PolicyEvaluator, TrustedCatalog
from verifiable_task_lifecycles.task_creation import (
    prepare_task_instance, register_task_instance,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, help="JSON with Intent and trusted catalog")
    parser.add_argument("--store", required=True, help="Directory for content-addressed artifacts")
    parser.add_argument("--instance-id", help="Optional fixed nonzero bytes32 task ID")
    parser.add_argument("--send", action="store_true", help="Explicitly authorize a live creation tx")
    parser.add_argument("--rpc-url", default=os.environ.get("BASE_SEPOLIA_RPC_URL"))
    parser.add_argument("--contract", default=os.environ.get("LIFECYCLE_CONTRACT_ADDRESS"))
    parser.add_argument("--key-env", default="EVM_PRIVATE_KEY", help="Name of private-key env variable")
    args = parser.parse_args()

    raw = json.loads(Path(args.config).read_text(encoding="utf-8"))
    if set(raw) != {"intent", "catalog"}:
        parser.error("config must contain exactly 'intent' and 'catalog'")
    intent_raw = raw["intent"]
    intent = Intent(
        goal=intent_raw["goal"],
        budget=intent_raw["budget"],
        allowed_services=tuple(intent_raw["allowed_services"]),
        allowed_providers=tuple(intent_raw["allowed_providers"]),
    )
    catalog = TrustedCatalog([CatalogEntry(**record) for record in raw["catalog"]])
    store = ArtifactStore(args.store)
    prepared = prepare_task_instance(
        intent=intent, evaluator=PolicyEvaluator(catalog), store=store,
        instance_id=args.instance_id,
    )

    if not args.send:
        print(json.dumps({
            "status": "prepared_offline_not_recorded",
            **prepared.contract_arguments,
            "artifact_store": str(store.root),
        }, indent=2))
        return

    if not args.rpc_url or not args.contract or not os.environ.get(args.key_env):
        parser.error(
            "--send requires --rpc-url (or BASE_SEPOLIA_RPC_URL), "
            "--contract (or LIFECYCLE_CONTRACT_ADDRESS), and a key in " + args.key_env
        )
    from verifiable_task_lifecycles.web3_instance_recorder import Web3InstanceRecorder

    gateway = Web3InstanceRecorder(
        rpc_url=args.rpc_url,
        contract_address=args.contract,
        private_key=os.environ[args.key_env],
    )
    created = register_task_instance(
        prepared=prepared, intent=intent, store=store, recorder=gateway
    )
    print(json.dumps({
        "status": "confirmed_onchain",
        **prepared.contract_arguments,
        "creation_tx": created.transaction_hash,
        "manifest": str(created.manifest_path),
    }, indent=2))


if __name__ == "__main__":
    main()
