#!/usr/bin/env python3
"""One-shot guarded x402 Base Sepolia live payment + independent ERC-20 audit.

Default: read-only HTTP 402 preflight and no wallet access. --send is a one-shot
paid request only after explicit acknowledgement. Never retry uncertain outcomes.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.metadata
import json
import os
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from verifiable_task_lifecycles.live_payment_probe import (
    LivePreflightError, LiveX402Config, check_negative_control,
    preflight_live_challenge,
)
from verifiable_task_lifecycles.payment_assurance import verify_erc20_transfer


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def prepare_journal(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = (json.dumps(payload, indent=2, sort_keys=True) + '\n').encode()
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(content)
            out.flush()
            os.fsync(out.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def save_journal(path: Path, payload: dict[str, Any]) -> None:
    content = (json.dumps(payload, indent=2, sort_keys=True) + '\n').encode()
    fd, tmp_name = tempfile.mkstemp(prefix='.x402-', suffix='.json', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as out:
            out.write(content)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def inspect_wallet_and_asset(rpc_url: str, config: LiveX402Config, key: str) -> tuple[Any, str, dict[str, Any]]:
    from eth_account import Account
    from web3 import Web3

    w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={'timeout': 15}))
    if int(w3.eth.chain_id) != 84532:
        raise LivePreflightError('RPC is not Base Sepolia (chain ID 84532)')
    account = Account.from_key(key)
    asset = Web3.to_checksum_address(config.asset)
    contract = w3.eth.contract(address=asset, abi=[
        {'type': 'function', 'name': 'decimals', 'stateMutability': 'view',
         'inputs': [], 'outputs': [{'type': 'uint8', 'name': ''}]},
        {'type': 'function', 'name': 'balanceOf', 'stateMutability': 'view',
         'inputs': [{'type': 'address', 'name': 'account'}],
         'outputs': [{'type': 'uint256', 'name': ''}]},
    ])
    if not w3.eth.get_code(asset):
        raise LivePreflightError('trusted ERC-20 contract has no bytecode')
    decimals = int(contract.functions.decimals().call())
    if decimals != 6:
        raise LivePreflightError(f'trusted test USDC has unexpected decimals={decimals}')
    balance = int(contract.functions.balanceOf(account.address).call())
    if balance < config.terms().atomic_amount:
        raise LivePreflightError(
            'test wallet does not have sufficient Base Sepolia USDC; '
            'obtain test tokens before initiating a payment'
        )
    return w3, account.address, {
        'chain_id': 84532, 'token_decimals': decimals,
        'payer': account.address, 'usdc_balance_atomic_before': balance,
    }


async def run(args: argparse.Namespace) -> int:
    config = LiveX402Config.load(args.config)
    negative = check_negative_control(config.terms())
    if not args.send:
        report: dict[str, Any] = {
            'mode': 'read-only-preflight', 'actual_payments': False,
            'trusted_catalog': config.safe_description(),
            'negative_control': negative,
        }
        try:
            report['challenge'] = await preflight_live_challenge(config)
            report['status'] = 'ready-for-explicit-send'
        except Exception as exc:
            report['status'] = 'blocked-no-payment'
            report['error_type'] = type(exc).__name__
            report['error'] = str(exc)[:300] if isinstance(exc, LivePreflightError) else 'provider/network preflight unavailable'
        print(json.dumps(report, indent=2))
        return 0 if report['status'] == 'ready-for-explicit-send' else 2

    if not args.acknowledge_one_testnet_payment:
        raise LivePreflightError('--send requires --acknowledge-one-testnet-payment')
    if not args.journal:
        raise LivePreflightError('--send requires explicit --journal path for durable recovery')
    journal_path = Path(args.journal).resolve()
    journal: dict[str, Any] = {
        'schema': 'live-x402-transfer-experiment/v1',
        'created_utc': now(), 'session_id': str(uuid.uuid4()),
        'mode': 'one-shot-onchain-settlement', 'status': 'initialized-no-payment',
        'trusted_catalog': config.safe_description(), 'negative_control': negative,
        'paid_request_attempts': 0, 'retry_policy': 'never automatic; reconcile first',
        'actual_payments': 'not_yet_known',
        'journal_warning': 'Sensitive wallet secrets and payment signatures are not archived',
    }
    prepare_journal(journal_path, journal)

    def checkpoint(status: str, **values: Any) -> None:
        journal.update(values)
        journal['status'] = status
        journal['updated_utc'] = now()
        save_journal(journal_path, journal)

    try:
        quote = await preflight_live_challenge(config)
        checkpoint('preflight-pass-no-payment', challenge=quote)
        key = os.getenv('EVM_PRIVATE_KEY')
        if not key:
            raise LivePreflightError('EVM_PRIVATE_KEY missing; no payment started')
        web3, payer, checks = inspect_wallet_and_asset(args.rpc_url, config, key)
        checkpoint('wallet-check-pass-no-payment', wallet_check=checks)
    except Exception as exc:
        checkpoint('blocked-no-payment', error_type=type(exc).__name__,
                   error=(str(exc)[:300] if isinstance(exc, LivePreflightError) else 'preflight/RPC/wallet validation error'))
        print(json.dumps({'status': journal['status'], 'journal': str(journal_path),
                          'error': journal['error']}, indent=2))
        return 2

    try:
        journal['sdk_version'] = importlib.metadata.version('x402')
    except importlib.metadata.PackageNotFoundError:
        checkpoint('blocked-no-payment', error_type='SdkMissing',
                   error='x402 SDK not installed; no paid request started')
        print(json.dumps({'status': journal['status'], 'journal': str(journal_path)}, indent=2))
        return 2
    if journal['sdk_version'] != '2.22.0':
        checkpoint('blocked-no-payment', error_type='UnpinnedSdk',
                   error='install pinned x402==2.22.0 before sending')
        print(json.dumps({'status': journal['status'], 'journal': str(journal_path)}, indent=2))
        return 2
    save_journal(journal_path, journal)
    from verifiable_task_lifecycles.x402_client import (
        X402PaymentClient, ServiceResponseFailedAfterSettlement,
    )
    # The durable attempt marker is written BEFORE anything could sign or spend.
    checkpoint('payment-attempt-in-progress', paid_request_attempts=1,
               actual_payments='unknown-until-chain-audited')

    try:
        client = X402PaymentClient(key)
        response = await client.request(config.method, config.endpoint, terms=config.terms(),
                                        json_body=config.json_body)
        body_encoded = json.dumps(response.body, sort_keys=True, ensure_ascii=False, default=str).encode()
        checkpoint('provider-reported-settlement', settlement_tx=response.transaction,
                   settlement_reported_network=response.network,
                   reported_payer=response.payer,
                   service_response='success',
                   provider_response_sha256='0x' + hashlib.sha256(body_encoded).hexdigest())
    except ServiceResponseFailedAfterSettlement as exc:
        checkpoint('provider-reported-settlement-service-failed', settlement_tx=exc.transaction,
                   service_response='failed', http_status=exc.status_code)
    except Exception as exc:
        # An error after the request begins cannot establish whether the
        # facilitator settled; do not automatically retry even on HTTP errors.
        checkpoint('payment-outcome-uncertain', error_type=type(exc).__name__,
                   error='Paid request failed or proof absent; reconcile before any new attempt')
        print(json.dumps({'status': journal['status'], 'journal': str(journal_path),
                          'paid_request_attempts': 1, 'warning': 'NO RETRY'}, indent=2))
        return 3

    # Independent log evidence, not the provider's PAYMENT-RESPONSE claim.
    check = verify_erc20_transfer(
        web3, reference=journal['settlement_tx'], payer=payer, expected=config.terms(),
        min_confirmations=args.min_confirmations,
    )
    result = check.as_dict()
    checkpoint('settlement-audit-' + check.status,
               independent_erc20_transfer_check=result,
               actual_payments=('one-matching-erc20-transfer-observed' if check.status == 'pass'
                                else 'unverified-or-mismatched'),
               service_response=journal['service_response'])
    print(json.dumps({
        'status': journal['status'], 'journal': str(journal_path),
        'settlement_tx': journal['settlement_tx'],
        'service_response': journal['service_response'],
        'independent_erc20_transfer_check': result,
        'paid_request_attempts': 1,
        'warning': 'Do not retry uncertain settlement or failed service response',
    }, indent=2))
    return 0 if check.status == 'pass' and journal['service_response'] == 'success' else 3


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', default='examples/live_sanctions_testnet.json')
    p.add_argument('--rpc-url', default='https://sepolia.base.org')
    p.add_argument('--send', action='store_true', help='Make exactly one real testnet paid HTTP request')
    p.add_argument('--acknowledge-one-testnet-payment', action='store_true')
    p.add_argument('--journal', help='Required for --send; new file, never overwritten')
    p.add_argument('--min-confirmations', type=int, default=1)
    args = p.parse_args()
    try:
        if type(args.min_confirmations) is not int or args.min_confirmations < 1:
            raise LivePreflightError('min-confirmations must be >= 1')
        return asyncio.run(run(args))
    except (LivePreflightError, ValueError, OSError) as exc:
        print(json.dumps({'status': 'blocked-no-payment', 'reason': str(exc)}, indent=2))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
