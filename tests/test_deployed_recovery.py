"""No network or private keys. Pinned legacy ABI and fail-closed recovery tests."""
from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from verifiable_task_lifecycles.adversarial_experiment import (
    SimulatedTaskLedger, prepare_adversarial_experiment,
)
from verifiable_task_lifecycles.adversarial_recovery import (
    CREATION_EVENT_TOPIC, CREATION_SELECTOR, RecoveryError,
    reconcile_recorded_prefix,
)
from verifiable_task_lifecycles.artifact_store import ArtifactStore
from verifiable_task_lifecycles.deployed_contract_profile import (
    DEPLOYED_LEGACY_ADDRESS, DEPLOYED_LEGACY_RUNTIME_KECCAK,
    DEPLOYED_LEGACY_READ_ABI, DEPLOYED_LEGACY_WRITES_ABI, contract_profile,
)
from verifiable_task_lifecycles.model import Intent
from verifiable_task_lifecycles.policy import CatalogEntry, PolicyEvaluator, TrustedCatalog
from verifiable_task_lifecycles.web3_experiment_recorder import Web3ExperimentRecorder
from verifiable_task_lifecycles.web3_task_reader import Web3TaskReader

CREATOR = "0xF482471FE90aC83376554054c039F188CB6CFA87"
TX = "0x" + "ab" * 32


class MockEth:
    def __init__(self, tx, receipt):
        self.tx = tx
        self.receipt = receipt
    def get_transaction(self, tx_hash):
        return self.tx
    def get_transaction_receipt(self, tx_hash):
        return self.receipt


class RecorderFunction:
    def __init__(self, capture, value=None, tx=False):
        self.capture = capture
        self.value = value
        self.tx = tx
    def call(self, opts=None, block_identifier=None):
        if self.tx:
            self.capture['preflight'] = opts
        return self.value
    def build_transaction(self, options):
        self.capture['tx_options'] = options
        return options


class DeployedFunctions:
    def __init__(self, capture, instance_before, transition):
        self.capture = capture
        self.before = instance_before
        self.transition = transition
    def instances(self, raw):
        self.capture['instance_read'] = bytes(raw)
        response = list(self.before)
        if self.capture.get('readback'):
            response[4] = self.before[4] + 1
        return RecorderFunction(self.capture, response)
    def transitions(self, raw, index):
        self.capture['transition_read'] = index
        return RecorderFunction(self.capture, self.transition)
    def recordTransition(self, *args):
        self.capture['record_args'] = args
        return RecorderFunction(self.capture, tx=True)


class RecorderMockW3:
    def __init__(self, capture):
        self.capture = capture
        self.eth = SimpleNamespace(
            chain_id=84532,
            get_transaction_count=lambda addr, when: 4,
            account=SimpleNamespace(sign_transaction=self.sign),
            send_raw_transaction=self.send,
            wait_for_transaction_receipt=self.wait,
        )
    def sign(self, tx, key):
        return SimpleNamespace(raw_transaction=b'signed')
    def send(self, raw):
        self.capture['sent'] = True
        return bytes.fromhex('cd' * 32)
    def wait(self, tx_hash, timeout):
        self.capture['readback'] = True
        return {'status': 1, 'blockNumber': 1234}
    def to_hex(self, raw):
        return '0x' + bytes(raw).hex()


class DeployedInterfaceAndRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = ArtifactStore(Path(self.tmp.name) / 'artifacts')
        catalog = TrustedCatalog([
            CatalogEntry(service='reputation', provider='controlled', value=2, endpoint='https://example.invalid/a',
                         pay_to='0x0000000000000000000000000000000000000001', equivalence_group='reputation-class'),
            CatalogEntry(service='reputation-alt', provider='controlled', value=3, endpoint='https://example.invalid/b',
                         pay_to='0x0000000000000000000000000000000000000001', equivalence_group='reputation-class'),
        ])
        intent = Intent('assess risk', 10, ('reputation', 'reputation-alt'), ('controlled',))
        self.experiment = prepare_adversarial_experiment(
            intent=intent, evaluator=PolicyEvaluator(catalog), store=self.store,
        )
        self.ledger = SimulatedTaskLedger(self.experiment)
        self.ledger._instance = replace(self.ledger._instance, creator=CREATOR)
        p = self.experiment.prepared
        self.journal = {
            'schema': 'admission-replay-experiment-journal/v1',
            'instance_id': '0x' + p.instance_id,
            'intent_hash': '0x' + p.intent_id,
            'model_hash': '0x' + p.model_id,
            'policy_hash': '0x' + p.policy_id,
            'contract': DEPLOYED_LEGACY_ADDRESS,
            'actual_payments': False,
            'transitions': [t.as_dict() for t in self.experiment.transitions],
        }
        creator_topic = bytes.fromhex(CREATOR.removeprefix('0x')).rjust(32, b'\x00')
        self.tx = {
            'to': DEPLOYED_LEGACY_ADDRESS,
            'from': CREATOR,
            'input': CREATION_SELECTOR + b''.join(bytes.fromhex(self.journal[k][2:])
                for k in ('instance_id','intent_hash','model_hash','policy_hash')),
        }
        self.receipt = {
            'status': 1,
            'to': DEPLOYED_LEGACY_ADDRESS,
            'logs': [{'address': DEPLOYED_LEGACY_ADDRESS,
                      'topics':[CREATION_EVENT_TOPIC, bytes.fromhex(p.instance_id), creator_topic],
                      'data':(1).to_bytes(32,'big')}],
        }

    def reconcile(self, journal=None):
        return reconcile_recorded_prefix(
            journal=self.journal if journal is None else journal,
            creation_tx=TX, store=self.store, ledger=self.ledger,
            w3=SimpleNamespace(eth=MockEth(self.tx,self.receipt)),
        )

    def test_live_reader_autodetects_pinned_abi(self):
        capture = {}
        known_hash = bytes.fromhex(DEPLOYED_LEGACY_RUNTIME_KECCAK[2:])
        class FakeWeb3:
            @staticmethod
            def HTTPProvider(url):
                return url
            @staticmethod
            def to_checksum_address(address):
                return address
            @staticmethod
            def keccak(data):
                return known_hash
            @staticmethod
            def to_hex(data):
                return '0x'+bytes(data).hex()
            def __init__(self, provider):
                self.eth=SimpleNamespace(
                    chain_id=84532, block_number=123456,
                    get_code=lambda address: b'known-deployed-code',
                    contract=lambda **kw: capture.update(kw) or SimpleNamespace(),
                )
        with patch.dict(sys.modules, {'web3': SimpleNamespace(Web3=FakeWeb3)}):
            reader=Web3TaskReader(rpc_url='unused',contract_address=DEPLOYED_LEGACY_ADDRESS)
        self.assertEqual(reader.contract_profile,'deployed-legacy')
        self.assertEqual(capture['abi'],DEPLOYED_LEGACY_READ_ABI)
        self.assertEqual(reader.block_number,123456)

    def test_live_recorder_autodetects_pinned_write_abi(self):
        capture = []
        known_hash = bytes.fromhex(DEPLOYED_LEGACY_RUNTIME_KECCAK[2:])
        class FakeWeb3:
            @staticmethod
            def HTTPProvider(url):
                return url
            @staticmethod
            def to_checksum_address(address):
                return address
            @staticmethod
            def keccak(data):
                return known_hash
            @staticmethod
            def to_hex(data):
                return '0x'+bytes(data).hex()
            def __init__(self, provider):
                self.eth=SimpleNamespace(
                    chain_id=84532, get_code=lambda address: b'known-deployed-code',
                    account=SimpleNamespace(from_key=lambda key:SimpleNamespace(address=CREATOR,key=b'nonsecret')),
                    contract=lambda **kw: capture.append(kw) or SimpleNamespace(address=kw['address']),
                )
        with patch.dict(sys.modules, {'web3': SimpleNamespace(Web3=FakeWeb3)}):
            recorder=Web3ExperimentRecorder(rpc_url='unused',contract_address=DEPLOYED_LEGACY_ADDRESS,private_key='mock')
        self.assertEqual(recorder.contract_profile,'deployed-legacy')
        self.assertEqual(capture[-1]['abi'], DEPLOYED_LEGACY_READ_ABI+DEPLOYED_LEGACY_WRITES_ABI)

    def test_known_selectors_have_correct_abi_types(self):
        self.assertEqual(DEPLOYED_LEGACY_READ_ABI[0]['name'], 'instances')
        self.assertEqual(DEPLOYED_LEGACY_READ_ABI[1]['name'], 'transitions')
        self.assertEqual([f['type'] for f in DEPLOYED_LEGACY_WRITES_ABI[1]['inputs']],
                         ['bytes32','bytes32','bytes32','bytes32','uint8'])
        self.assertEqual(CREATION_SELECTOR.hex(), 'd831bba8')
        self.assertEqual(CREATION_EVENT_TOPIC.hex()[:8], 'b83bd3e1')

    def test_profile_recognizes_pinned_code_and_rejects_substitution(self):
        w3 = SimpleNamespace(eth=SimpleNamespace(chain_id=84532),
                             keccak=lambda code: bytes.fromhex(DEPLOYED_LEGACY_RUNTIME_KECCAK[2:]),
                             to_hex=lambda value: '0x'+value.hex())
        self.assertEqual(contract_profile(w3, DEPLOYED_LEGACY_ADDRESS, b'code'), 'deployed-legacy')
        w3.keccak = lambda code: bytes.fromhex('aa' * 32)
        with self.assertRaisesRegex(ValueError, 'unexpected runtime code'):
            contract_profile(w3, DEPLOYED_LEGACY_ADDRESS, b'code')
        self.assertEqual(contract_profile(w3, '0x'+'12'*20, b'code'), 'source')

    def test_reconciles_confirmed_creation_without_sending_anything(self):
        r = self.reconcile()
        self.assertEqual(r.transition_count, 0)
        self.assertTrue(r.report.recorded_policy_verified)
        self.assertEqual(r.report.settlement_check, 'unverified')

    def test_reconciles_first_and_second_exact_recorded_prefix(self):
        self.ledger.append(self.experiment.transitions[0])
        first = self.reconcile()
        self.assertEqual(first.transition_count, 1)
        self.assertEqual(first.report.admission_replay, 'pass')
        self.ledger.append(self.experiment.transitions[1])
        second = self.reconcile()
        self.assertEqual(second.transition_count, 2)
        self.assertEqual(second.report.structural_consistency, 'pass')
        self.assertEqual(second.report.admission_replay, 'fail')
        self.assertEqual(second.report.denied_transition, 1)

    def test_rejects_nonmatching_existing_transition(self):
        self.ledger.append(self.experiment.transitions[0])
        from verifiable_task_lifecycles.committed_verifier import LedgerTransition
        t = self.ledger._records[0]
        self.ledger._records[0] = replace(t, action_hash='0x'+'ff'*32)
        with self.assertRaisesRegex(RecoveryError,'differs from prepared'):
            self.reconcile()

    def test_rejects_tampered_artifacts(self):
        self.journal['transitions'][0]['action_hash']='0x'+'ff'*32
        with self.assertRaisesRegex(RecoveryError, 'artifact missing'):
            self.reconcile()

    def test_rejects_changed_creation_calldata(self):
        self.tx['input'] = CREATION_SELECTOR + bytes(128)
        with self.assertRaisesRegex(RecoveryError, 'calldata differs'):
            self.reconcile()

    def test_rejects_missing_creation_event(self):
        self.receipt['logs']=[]
        with self.assertRaisesRegex(RecoveryError, 'event absent'):
            self.reconcile()

    def test_rejects_wrong_creator(self):
        self.ledger._instance=replace(self.ledger._instance, creator='0x'+'22'*20)
        with self.assertRaisesRegex(RecoveryError, 'expected active task'):
            self.reconcile()

    def test_legacy_recorder_uses_five_arg_record_transition_and_mapping_readback(self):
        capture={}
        a = bytes.fromhex('11'*32);p=bytes.fromhex('22'*32);e=bytes.fromhex('33'*32)
        funcs=DeployedFunctions(capture,[b'\x00'*32]*3+[1,0,CREATOR],[1,a,p,e,1])
        rec=object.__new__(Web3ExperimentRecorder)
        rec.contract_profile='deployed-legacy'
        rec.confirmation_timeout=60
        rec.account=SimpleNamespace(address=CREATOR, key=b'test-key')
        rec.w3=RecorderMockW3(capture)
        rec.contract=SimpleNamespace(functions=funcs)
        result=rec.record_transition(instance_id=self.journal['instance_id'],
                expected_index=0, action_hash='0x'+a.hex(), payment_hash='0x'+p.hex(),
                evidence_hash='0x'+e.hex())
        self.assertEqual(result,'0x'+'cd'*32)
        self.assertEqual(len(capture['record_args']),5)
        self.assertEqual(capture['record_args'][-1],1)
        self.assertTrue(capture.get('sent'))
        self.assertEqual(capture.get('transition_read'),0)

    def test_deployed_reader_decodes_public_mapping_getters(self):
        ids=[]
        i=[bytes.fromhex('aa'*32), bytes.fromhex('bb'*32), bytes.fromhex('cc'*32),1,0,CREATOR]
        t=[1,bytes.fromhex('11'*32),bytes.fromhex('22'*32),bytes.fromhex('33'*32),1]
        class Functions:
            def instances(self, raw):
                ids.append('instances')
                return SimpleNamespace(call=lambda **kwargs:i)
            def transitions(self, raw, index):
                ids.append(('transitions',index))
                return SimpleNamespace(call=lambda **kwargs:t)
        reader=object.__new__(Web3TaskReader)
        reader.contract_profile='deployed-legacy'
        reader.block_number=58307062
        reader.contract=SimpleNamespace(functions=Functions())
        result=reader.get_instance(self.journal['instance_id'])
        self.assertEqual(result.transition_count,0)
        self.assertEqual(result.creator.lower(),CREATOR.lower())
        record=reader.get_transition(self.journal['instance_id'],0)
        self.assertEqual(record.evidence_hash,'0x'+'33'*32)
        self.assertEqual(ids,['instances',('transitions',0)])


if __name__=='__main__':
    unittest.main()
