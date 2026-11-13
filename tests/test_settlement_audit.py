"""Step 5 task-aware settlement audit with ledger and Web3 test doubles."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from verifiable_task_lifecycles.artifact_store import ArtifactStore
from verifiable_task_lifecycles.committed_verifier import LedgerInstance, LedgerTransition, verify_committed_task
from verifiable_task_lifecycles.model import ActionProposal, Evidence, Intent, Payment, TaskState
from verifiable_task_lifecycles.policy import CatalogEntry, PolicyEvaluator, TrustedCatalog
from verifiable_task_lifecycles.settlement_audit import audit_committed_settlements
from verifiable_task_lifecycles.task_creation import prepare_task_instance
from verifiable_task_lifecycles.payment_assurance import _TRANSFER_TOPIC

NETWORK='eip155:84532'
TOKEN='0x'+'a1'*20
PAYTO='0x'+'b2'*20
PAYER='0x'+'c3'*20
TX='0x'+'d4'*32


class Ledger:
    def __init__(self,i,record): self.id='0x'+i; self.record=record; self.transitions=[]
    def get_instance(self,i):
        if i.lower().removeprefix('0x')!=self.id[2:]: raise LookupError('unexpected instance')
        return self.record
    def get_transition(self,i,n): return self.transitions[n]


class Web3:
    def __init__(self,*,logs=None,block=200,chain=84532):
        self.eth=self; self.chain_id=chain; self.block_number=block
        self.receipt={'status':1,'blockNumber':198,'logs':logs if logs is not None else [self.transfer()]}
    @staticmethod
    def transfer(amount=10000,token=TOKEN,to=PAYTO):
        topic=lambda addr:'0x'+'0'*24+addr[2:]
        return dict(address=token,topics=[_TRANSFER_TOPIC,topic(PAYER),topic(to)],data='0x'+f'{amount:064x}')
    def get_transaction_receipt(self,ref):
        if ref!=TX: raise RuntimeError('receipt not found')
        return self.receipt


class SettlementAuditTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.store=ArtifactStore(temp.name)
        self.catalog=TrustedCatalog([CatalogEntry('history','controlled',1,'http://x',PAYTO,'history')])
        self.intent=Intent('risk',10,('history',),('controlled',))
        self.prepared=prepare_task_instance(intent=self.intent,evaluator=PolicyEvaluator(self.catalog),store=self.store)
        self.ledger=Ledger(self.prepared.instance_id,LedgerInstance('0x'+self.prepared.intent_id,
                         '0x'+self.prepared.model_id,'0x'+self.prepared.policy_id,TaskState.ACTIVE,0,'0xcreator'))

    def append(self,reference=TX,network=NETWORK,protocol='x402-v2'):
        action=self.catalog.resolve(ActionProposal('history'))
        aid=self.store.put(action.as_artifact())
        payment=Payment(reference,PAYER,action.provider,action.value,aid,protocol,network)
        evidence=Evidence(self.prepared.instance_id,aid,'{}','success',reference)
        pid=self.store.put(payment.as_artifact());eid=self.store.put(evidence.as_artifact())
        self.ledger.transitions.append(LedgerTransition(TaskState.ACTIVE,'0x'+aid,'0x'+pid,'0x'+eid,TaskState.ACTIVE))
        self.ledger.record=replace(self.ledger.record,transition_count=1)

    def audit(self,web3=None):
        rep=verify_committed_task(instance_id=self.prepared.instance_id,ledger=self.ledger,store=self.store)
        self.assertEqual(rep.structural_consistency,'pass')
        return audit_committed_settlements(instance_id='0x'+self.prepared.instance_id,ledger=self.ledger,
             store=self.store,recorded_report=rep,web3=web3 or Web3(),network=NETWORK,
             asset=TOKEN,atomic_units_per_budget_unit=10000)

    def test_committed_payment_with_matching_erc20_transfer_passes(self):
        self.append(); r=self.audit()
        self.assertEqual(r.status,'pass');self.assertEqual(r.checks[0].observed_amount,10000)

    def test_token_amount_mismatch_fails(self):
        self.append();r=self.audit(Web3(logs=[Web3.transfer(amount=11000)]))
        self.assertEqual(r.status,'fail')

    def test_wrong_payee_fails(self):
        self.append();r=self.audit(Web3(logs=[Web3.transfer(to='0x'+'f1'*20)]))
        self.assertEqual(r.status,'fail')

    def test_synthetic_payment_never_passes(self):
        self.append(reference='SIMULATED-NO-SETTLEMENT:index:0')
        self.assertEqual(self.audit().status,'unverified')

    def test_network_mismatch_fails(self):
        self.append(network='eip155:8453')
        self.assertEqual(self.audit().status,'fail')

    def test_other_protocol_unverified(self):
        self.append(protocol='unknown-protocol')
        self.assertEqual(self.audit().status,'unverified')

    def test_empty_history_unverified(self):
        self.assertEqual(self.audit().status,'unverified')

    def test_untrusted_policy_source_unverified(self):
        self.append()
        rep=verify_committed_task(instance_id=self.prepared.instance_id,ledger=self.ledger,store=self.store)
        rep.admission_replay='unverified'
        r=audit_committed_settlements(instance_id='0x'+self.prepared.instance_id,ledger=self.ledger,
            store=self.store,recorded_report=rep,web3=Web3(),network=NETWORK,
            asset=TOKEN,atomic_units_per_budget_unit=10000)
        self.assertEqual(r.status,'unverified')


if __name__=='__main__': unittest.main()
