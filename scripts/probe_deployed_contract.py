#!/usr/bin/env python3
"""Read-only probe of the *deployed* Base Sepolia LifecycleTracker interface.

No signing, writing, resubmitting or wallet credentials. Does not alter the
existing experiment journal. Identifies the observed instance-creation event,
reports bytecode selectors and probes plausible read methods (only when their
selectors are present in the deployed bytecode).

Usage:
  PYTHONPATH=src python scripts/probe_deployed_contract.py \
    --journal experiments/admission_replay/results/INSTANCE.json \
    --tx 0x... --rpc-url https://sepolia.base.org --output probe.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

DEPLOYED_EVENT_SIGNATURE = 'InstanceCreated(bytes32,address,uint8)'
CREATE_SIGNATURE = 'createInstance(bytes32,bytes32,bytes32,bytes32)'
# Plausible read signatures only, not claims about the deployed contract.
CANDIDATE_VIEWS = (
    'getInstance(bytes32)',
    'instances(bytes32)',
    'instance(bytes32)',
    'getTask(bytes32)',
    'tasks(bytes32)',
    'getTaskInstance(bytes32)',
    'taskInstances(bytes32)',
    'instanceInfo(bytes32)',
    'getInstanceInfo(bytes32)',
    'getTaskInfo(bytes32)',
    'getInstanceState(bytes32)',
    'getTaskState(bytes32)',
    'getTransition(bytes32,uint64)',
    'getTransition(bytes32,uint256)',
    'transitions(bytes32,uint64)',
    'transitions(bytes32,uint256)',
    'transitionRecords(bytes32,uint64)',
    'transitionRecords(bytes32,uint256)',
)


def hex32(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r'(?:0x)?[0-9a-fA-F]{64}', value):
        raise ValueError('expected bytes32 hex')
    return value.removeprefix('0x').lower()


def push4_immediates(code: bytes) -> set[str]:
    out = set()
    index = 0
    while index < len(code):
        op = code[index]
        if op == 0x63 and index + 5 <= len(code):
            out.add('0x' + code[index + 1:index + 5].hex())
        index += 1 + (op - 0x5f if 0x60 <= op <= 0x7f else 0)
    return out


def validate_creation_event(*, topics: list[bytes], data: bytes,
                            expected_topic: bytes, instance_id: str,
                            expected_creator: str) -> dict[str, Any] | None:
    """Decode 3-field deployed event; no trust in a local 5-field ABI."""
    if len(topics) != 3 or bytes(topics[0]) != expected_topic or len(data) != 32:
        return None
    state = int.from_bytes(data, 'big')
    observed_instance = '0x' + bytes(topics[1]).hex()
    observed_creator = '0x' + bytes(topics[2])[-20:].hex()
    return {
        'signature': DEPLOYED_EVENT_SIGNATURE,
        'instance_id': observed_instance,
        'creator': observed_creator,
        'state_value': state,
        'instance_matches_journal': hex32(observed_instance) == hex32(instance_id),
        'creator_matches_tx_sender': observed_creator.lower() == expected_creator.lower(),
        'state_is_active': state == 1,
    }


def explain_view_return(raw: bytes, journal: dict[str, Any], archive: dict[str, Any] | None = None) -> dict[str, Any]:
    """Keep raw words: unknown ABI output order must not be assumed."""
    n = len(raw) // 32
    words = [raw[i * 32:(i + 1) * 32].hex() for i in range(n)]
    found = {}
    for key in ('intent_hash', 'model_hash', 'policy_hash'):
        if key in journal and hex32(journal[key]) in words:
            found[key] = words.index(hex32(journal[key]))
    if archive:
        for key in ('model_hash', 'policy_hash'):
            if key in archive and hex32(archive[key]) in words:
                found['archived_' + key] = words.index(hex32(archive[key]))
    return {
        'raw_byte_length': len(raw),
        'word_aligned': len(raw) % 32 == 0,
        'word_count': n if len(raw) % 32 == 0 else None,
        'words_hex': ['0x' + w for w in words[:10]],
        'matched_commitment_word_indices': found,
    }


def inspect(*, rpc_url: str, tx_hash: str, journal_path: Path,
            archive_path: Path | None = None) -> dict[str, Any]:
    try:
        from web3 import Web3
    except ImportError as exc:
        raise RuntimeError("This diagnostic needs web3; run within your project venv") from exc
    journal = json.loads(journal_path.read_text(encoding='utf-8'))
    archive = json.loads(archive_path.read_text(encoding='utf-8')) if archive_path else None
    for key in ('instance_id','intent_hash','model_hash','policy_hash','contract'):
        if key not in journal:
            raise ValueError(f'journal missing {key}')
    if not re.fullmatch('0x[0-9a-fA-F]{64}', tx_hash):
        raise ValueError('invalid transaction hash')
    w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={'timeout': 20}))
    chain_id = int(w3.eth.chain_id)
    if chain_id != 84532:
        raise ValueError(f'Wrong chain: {chain_id} != 84532')
    address = Web3.to_checksum_address(journal['contract'])
    receipt = w3.eth.get_transaction_receipt(tx_hash)
    tx = w3.eth.get_transaction(tx_hash)
    if int(receipt['status']) != 1 or receipt.get('to','').lower() != address.lower() or tx.get('to','').lower() != address.lower():
        raise ValueError('creation transaction does not match a successful call to the expected contract')
    calldata = bytes(tx['input'])
    expected_input = Web3.keccak(text=CREATE_SIGNATURE)[:4] + b''.join(
        bytes.fromhex(hex32(journal[k]))
        for k in ('instance_id','intent_hash','model_hash','policy_hash')
    )
    if calldata != expected_input:
        raise ValueError('creation calldata does not match journal commitments')

    actual_event_topic = Web3.keccak(text=DEPLOYED_EVENT_SIGNATURE)
    matched_events = []
    for log in receipt['logs']:
        if log['address'].lower() != address.lower():
            continue
        ev = validate_creation_event(
            topics=list(log['topics']), data=bytes(log['data']),
            expected_topic=actual_event_topic, instance_id=journal['instance_id'],
            expected_creator=tx['from'],
        )
        if ev:
            matched_events.append(ev)

    bytecode = bytes(w3.eth.get_code(address, block_identifier='latest'))
    selectors = push4_immediates(bytecode)
    report: dict[str, Any] = {
        'mode': 'READ_ONLY_NO_TRANSACTIONS',
        'rpc_chain_id': chain_id,
        'contract': address,
        'tx': tx_hash,
        'receipt_status': 1,
        'calldata_matches_journal': True,
        'deployed_event_signature': DEPLOYED_EVENT_SIGNATURE,
        'deployed_event_topic0': Web3.to_hex(actual_event_topic),
        'creation_events': matched_events,
        'creation_event_matches': any(
            ev['instance_matches_journal'] and ev['creator_matches_tx_sender'] and ev['state_is_active']
            for ev in matched_events
        ),
        'bytecode': {
            'size': len(bytecode),
            'keccak256': Web3.to_hex(Web3.keccak(bytecode)),
            'all_push4_literals_heuristic': sorted(selectors),
        },
        'candidate_read_selectors': [],
    }
    
    current_id = bytes.fromhex(hex32(journal['instance_id']))
    archive_id = bytes.fromhex(hex32(archive['instance_id'])) if archive is not None else None
    for signature in CANDIDATE_VIEWS:
        selector = Web3.to_hex(Web3.keccak(text=signature)[:4])
        selector_seen = selector in selectors
        candidate: dict[str, Any] = {'signature':signature, 'selector':selector, 'selector_present_in_bytecode': selector_seen}
        if selector_seen:
            # Probe only signatures with a corresponding PUSH4 literal.
            # Every call here is eth_call, never a signed transaction.
            arg = current_id if signature.count(',') == 0 else current_id + (0).to_bytes(32,'big')
            try:
                response = bytes(w3.eth.call({'to':address,'data':selector + arg.hex()}, block_identifier='latest'))
                candidate['current_instance'] = explain_view_return(response, journal)
            except Exception as exc:
                candidate['current_instance'] = {'error':f'{type(exc).__name__}: {exc}'[:500]}
            if archive_id is not None:
                arg = archive_id if signature.count(',') == 0 else archive_id + (0).to_bytes(32,'big')
                try:
                    response = bytes(w3.eth.call({'to':address,'data':selector + arg.hex()}, block_identifier='latest'))
                    candidate['archived_instance'] = explain_view_return(response, journal, archive)
                except Exception as exc:
                    candidate['archived_instance'] = {'error':f'{type(exc).__name__}: {exc}'[:500]}
        report['candidate_read_selectors'].append(candidate)
    report['assessment'] = (
        'DEPLOYED_INSTANCE_CREATED_EVENT_MATCHES; DISCOVER_READ_INTERFACE'
        if report['creation_event_matches']
        else 'CREATION_EVENT_UNRESOLVED; DO_NOT_RESUBMIT'
    )
    return report


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--journal',type=Path,required=True)
    p.add_argument('--tx',required=True)
    p.add_argument('--archive',type=Path)
    p.add_argument('--rpc-url',default=os.environ.get('BASE_SEPOLIA_RPC_URL','https://sepolia.base.org'))
    p.add_argument('--output',type=Path)
    args=p.parse_args()
    try:
        result=inspect(rpc_url=args.rpc_url,tx_hash=args.tx,journal_path=args.journal,archive_path=args.archive)
        if args.output:
            with args.output.open('x',encoding='utf-8') as f:
                json.dump(result,f,indent=2,sort_keys=True)
                f.write('\n')
        print(json.dumps(result,indent=2,sort_keys=True))
        return 0
    except Exception as exc:
        print(f'PROBE_FAILED: {type(exc).__name__}: {exc}',file=sys.stderr)
        return 2

if __name__=='__main__':
    raise SystemExit(main())
