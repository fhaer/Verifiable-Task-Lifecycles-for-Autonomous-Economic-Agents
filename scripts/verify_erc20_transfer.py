#!/usr/bin/env python3
"""Read-only check of one ERC-20 transfer on an independently specified EVM network.

Expected token/recipient/payer/amount are trusted caller inputs, NOT proved
by a lifecycle commitment unless an additional committed-policy check is run.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from verifiable_task_lifecycles.payment_assurance import (
    AuthorizedPaymentTerms, verify_erc20_transfer,
)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--rpc-url", required=True)
    p.add_argument("--tx", required=True)
    p.add_argument("--network", required=True, help="e.g. eip155:84532")
    p.add_argument("--asset", required=True, help="trusted ERC-20 token contract")
    p.add_argument("--payer", required=True, help="expected token sender")
    p.add_argument("--recipient", required=True, help="expected token recipient")
    p.add_argument("--amount-atomic", required=True, type=int, help="expected exact base-unit amount")
    p.add_argument("--min-confirmations", type=int, default=1)
    a = p.parse_args()
    try:
        from web3 import Web3
        terms = AuthorizedPaymentTerms(a.network, a.asset, a.recipient, a.amount_atomic)
        w3 = Web3(Web3.HTTPProvider(a.rpc_url))
        result = verify_erc20_transfer(
            w3, reference=a.tx, payer=a.payer, expected=terms,
            min_confirmations=a.min_confirmations,
        )
        print(json.dumps(result.as_dict(), indent=2))
        return 0 if result.status == "pass" else 1
    except (ValueError, ImportError, OSError) as exc:
        print(json.dumps({"status": "unverified", "reason": str(exc)}, indent=2))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
