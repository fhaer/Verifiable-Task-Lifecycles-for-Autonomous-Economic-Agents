#!/usr/bin/env python3
"""Read-only diagnosis of an already submitted Step 4 createInstance transaction.

Does not sign, broadcast, retry, or update the original experiment journal.
Usage: PYTHONPATH=src python scripts/diagnose_deployment.py --journal PATH --tx 0x...
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

CREATE_SIGNATURE = 'createInstance(bytes32,bytes32,bytes32,bytes32)'
VIEW_SIGNATURE = 'getInstance(bytes32)'
TRANSITION_SIGNATURE = 'getTransition(bytes32,uint64)'
EVENT_SIGNATURE = 'InstanceCreated(bytes32,address,bytes32,bytes32,bytes32)'


def canonical_bytes32(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r'(?:0x)?[0-9a-fA-F]{64}', value):
        raise ValueError('expected a 32-byte hex value')
    return value.lower().removeprefix('0x')


def decode_create_input(raw: bytes, selector: bytes) -> list[str] | None:
    """Four static bytes32 arguments: no ABI dynamic offsets or special decoding."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != 4 + 32 * 4:
        return None
    if raw[:4] != selector:
        return None
    return [raw[4 + i * 32:4 + (i + 1) * 32].hex() for i in range(4)]


def decode_instance_return(raw: bytes) -> dict[str, Any] | None:
    """Decode the six static ABI words returned by getInstance(Instance memory)."""
    if len(raw) != 6 * 32:
        return None
    words = [raw[i:i + 32] for i in range(0, len(raw), 32)]
    if any(words[3][:-1]) or any(words[4][:-8]) or any(words[5][:-20]):
        return None
    return {
        'intent_hash': '0x' + words[0].hex(),
        'model_hash': '0x' + words[1].hex(),
        'policy_hash': '0x' + words[2].hex(),
        'state': int.from_bytes(words[3], 'big'),
        'transition_count': int.from_bytes(words[4], 'big'),
        'creator': '0x' + words[5][-20:].hex(),
    }


def push4_immediates(code: bytes) -> set[str]:
    """Inspect PUSH4 immediates in EVM bytecode (a heuristic, not an ABI proof).

    Skip all PUSH data to avoid false matches inside literals.
    """
    results: set[str] = set()
    index = 0
    while index < len(code):
        opcode = code[index]
        if opcode == 0x63 and index + 5 <= len(code):
            results.add('0x' + code[index + 1:index + 5].hex())
        if 0x60 <= opcode <= 0x7f:
            index += 1 + (opcode - 0x5f)
        else:
            index += 1
    return results


def summarize_logs(receipt: dict, expected_address: str) -> dict[str, Any]:
    """Preserve raw event topics/lengths, without assuming the source ABI."""
    entries = []
    for log in receipt['logs']:
        entries.append({
            'address': log['address'],
            'same_contract': log['address'].lower() == expected_address.lower(),
            'topics': ['0x' + bytes(topic).hex() for topic in log['topics']],
            'data_byte_length': len(bytes(log['data'])),
        })
    return {'count': len(entries), 'entries': entries}


def compare_archived_instance(data: dict[str, Any], archived: dict[str, Any]) -> dict[str, bool]:
    """Compare only fields independently recorded in the archived result."""
    comparisons = {
        'creator': data['creator'].lower() == archived['creator'].lower(),
        'model_hash': canonical_bytes32(data['model_hash']) == canonical_bytes32(archived['model_hash']),
        'policy_hash': canonical_bytes32(data['policy_hash']) == canonical_bytes32(archived['policy_hash']),
        'transition_count': data['transition_count'] == archived['transition_count'],
        'state': data['state'] == archived['final_state'],
    }
    return comparisons


def compact_exception(exc: Exception) -> str:
    msg = f'{type(exc).__name__}: {exc}'
    if exc.__cause__ is not None:
        msg += f'; cause={type(exc.__cause__).__name__}: {exc.__cause__}'
    return msg[:1500]


def _compare_view(data: dict[str, Any], journal: dict[str, Any], tx_from: str) -> bool:
    return (
        all(canonical_bytes32(data[k]) == canonical_bytes32(journal[k])
            for k in ('intent_hash', 'model_hash', 'policy_hash'))
        and data['state'] == 1
        and data['transition_count'] == 0
        and data['creator'].lower() == tx_from.lower()
    )


def inspect(*, rpc_url: str, journal_path: Path, tx_hash: str, archive_path: Path | None = None) -> dict[str, Any]:
    try:
        from web3 import Web3
    except ImportError as exc:
        raise RuntimeError("web3 is required: python -m pip install 'web3>=7,<8'") from exc

    journal = json.loads(journal_path.read_text(encoding='utf-8'))
    archive = json.loads(archive_path.read_text(encoding='utf-8')) if archive_path else None
    if archive is not None and not isinstance(archive.get('instance_id'), str):
        raise ValueError('archived instance identifier missing')
    for key in ('instance_id', 'intent_hash', 'model_hash', 'policy_hash', 'contract'):
        if key not in journal:
            raise ValueError(f'missing {key} in experiment journal')
    if not re.fullmatch(r'0x[0-9a-fA-F]{64}', tx_hash):
        raise ValueError('invalid transaction hash')
    contract_address = Web3.to_checksum_address(journal['contract'])
    expected = [canonical_bytes32(journal[key]) for key in
                ('instance_id', 'intent_hash', 'model_hash', 'policy_hash')]
    w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={'timeout': 20}))
    chain_id = int(w3.eth.chain_id)
    if chain_id != 84532:
        raise ValueError(f'RPC is on chain {chain_id}, not Base Sepolia (84532)')
    report: dict[str, Any] = {
        'mode': 'READ_ONLY_NO_TRANSACTIONS',
        'rpc_chain_id': chain_id,
        'journal': str(journal_path),
        'instance_id': '0x' + expected[0],
        'creation_tx': tx_hash,
        'contract': contract_address,
    }
    receipt = w3.eth.get_transaction_receipt(tx_hash)
    tx = w3.eth.get_transaction(tx_hash)
    block = int(receipt['blockNumber'])
    tx_to = tx.get('to')
    receipt_to = receipt.get('to')
    report.update({
        'receipt_status': int(receipt['status']),
        'block_number': block,
        'transaction_to_matches_contract': bool(tx_to and tx_to.lower() == contract_address.lower()),
        'receipt_to_matches_contract': bool(receipt_to and receipt_to.lower() == contract_address.lower()),
        'transaction_sender': tx['from'],
    })
    tx_input = bytes(tx['input'])
    decoded = decode_create_input(tx_input, Web3.keccak(text=CREATE_SIGNATURE)[:4])
    report['calldata_decoded'] = decoded is not None
    report['calldata_matches_journal'] = decoded == expected

    report['raw_receipt_logs'] = summarize_logs(receipt, contract_address)
    # Runtime bytecode is a more useful next clue than guessing ABI from a
    # successful receipt. Its hash alone is not an ABI or source verification.
    report['runtime_bytecode'] = {}
    for label, block_id in (('receipt_block', block), ('latest', 'latest')):
        try:
            code = bytes(w3.eth.get_code(contract_address, block_identifier=block_id))
            selectors = push4_immediates(code)
            report['runtime_bytecode'][label] = {
                'byte_length': len(code),
                'keccak256': Web3.to_hex(Web3.keccak(code)),
                'selector_heuristic': {
                    name: Web3.to_hex(Web3.keccak(text=sig)[:4]) in selectors
                    for name, sig in {
                        'createInstance': CREATE_SIGNATURE,
                        'getInstance': VIEW_SIGNATURE,
                        'getTransition': TRANSITION_SIGNATURE,
                    }.items()
                },
            }
        except Exception as exc:
            report['runtime_bytecode'][label] = {'error': compact_exception(exc)}

    event_topic0 = Web3.keccak(text=EVENT_SIGNATURE)
    logs_matched = []
    for log in receipt['logs']:
        if log['address'].lower() != contract_address.lower():
            continue
        topics = log['topics']
        if len(topics) != 3 or topics[0] != event_topic0:
            continue
        raw_data = bytes(log['data'])
        if len(raw_data) != 96:
            continue
        topic_instance = bytes(topics[1]).hex()
        creator = '0x' + bytes(topics[2])[-20:].hex()
        values = [raw_data[i:i + 32].hex() for i in (0, 32, 64)]
        logs_matched.append({
            'instance_matches_journal': topic_instance == expected[0],
            'commitments_match_journal': values == expected[1:],
            'creator_matches_tx_sender': creator.lower() == tx['from'].lower(),
        })
    report['instance_created_events'] = logs_matched
    report['creation_event_matches_journal'] = any(all(ev.values()) for ev in logs_matched)

    view_input = Web3.keccak(text=VIEW_SIGNATURE)[:4] + bytes.fromhex(expected[0])
    report['reads'] = {}
    for label, block_id in (('receipt_block', block), ('latest', 'latest')):
        try:
            raw_response = bytes(w3.eth.call({
                'to': contract_address,
                'data': Web3.to_hex(view_input),
            }, block_identifier=block_id))
            decoded_view = decode_instance_return(raw_response)
            report['reads'][label] = {
                'raw_byte_length': len(raw_response),
                'decoded': decoded_view,
                'matches_journal': (
                    _compare_view(decoded_view, journal, tx['from'])
                    if decoded_view is not None else False
                ),
            }
        except Exception as exc:
            report['reads'][label] = {'error': compact_exception(exc)}

    if archive is not None:
        known_id = canonical_bytes32(archive['instance_id'])
        known_call = Web3.keccak(text=VIEW_SIGNATURE)[:4] + bytes.fromhex(known_id)
        report['archived_instance_probe'] = {
            'instance_id': '0x' + known_id,
            'archived_verification_claim': archive.get('verified'),
        }
        for label, block_id in (('receipt_block', block), ('latest', 'latest')):
            try:
                response = bytes(w3.eth.call({
                    'to': contract_address,
                    'data': Web3.to_hex(known_call),
                }, block_identifier=block_id))
                decoded = decode_instance_return(response)
                report['archived_instance_probe'][label] = {
                    'raw_byte_length': len(response),
                    'decoded': decoded,
                    'comparisons': compare_archived_instance(decoded, archive) if decoded is not None else None,
                }
            except Exception as exc:
                report['archived_instance_probe'][label] = {'error': compact_exception(exc)}

    if report['reads'].get('latest', {}).get('matches_journal'):
        report['assessment'] = 'INSTANCE_EXISTS_AND_COMMITMENTS_MATCH; NO RETRY'
    elif report['creation_event_matches_journal'] and report['calldata_matches_journal']:
        report['assessment'] = 'CREATION_CONFIRMED_BY_EVENT_BUT_READBACK_UNAVAILABLE; NO RETRY'
    elif report['receipt_status'] == 1 and report['calldata_matches_journal']:
        report['assessment'] = 'TRANSACTION_SUCCESSFUL_BUT_CREATION_NOT_FULLY_CORROBORATED; NO RETRY'
    else:
        report['assessment'] = 'UNRESOLVED; NO RETRY'
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--journal', type=Path, required=True, help='existing experiment result/journal JSON')
    parser.add_argument('--tx', required=True, help='already submitted createInstance transaction hash')
    parser.add_argument('--rpc-url', default=os.environ.get('BASE_SEPOLIA_RPC_URL', 'https://sepolia.base.org'))
    parser.add_argument('--output', type=Path, help='optional path for separate diagnostic JSON; never overwrites')
    parser.add_argument('--archive', type=Path, help='optional archived independent-verification result for probing an existing instance')
    args = parser.parse_args()
    try:
        report = inspect(rpc_url=args.rpc_url, journal_path=args.journal, tx_hash=args.tx, archive_path=args.archive)
        if args.output is not None:
            with args.output.open('x', encoding='utf-8') as f:
                json.dump(report, f, indent=2, sort_keys=True)
                f.write('\n')
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except Exception as exc:
        print(f'READ_ONLY_DIAGNOSTIC_FAILED: {compact_exception(exc)}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
