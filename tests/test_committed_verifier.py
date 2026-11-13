"""Step 3: ledger-anchored deterministic admission replay (no RPC / payment)."""

import copy
import json
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from verifiable_task_lifecycles.artifact_store import ArtifactStore
from verifiable_task_lifecycles.canonical import content_id
from verifiable_task_lifecycles.committed_verifier import (
    LedgerInstance, LedgerTransition, verify_committed_task,
)
from verifiable_task_lifecycles.model import ActionProposal, Evidence, Intent, Payment, TaskState
from verifiable_task_lifecycles.policy import CatalogEntry, PolicyEvaluator, TrustedCatalog
from verifiable_task_lifecycles.task_creation import prepare_task_instance
from verifiable_task_lifecycles.web3_task_reader import Web3TaskReader


class FakeLedger:
    """Only simulates on-chain public reads; never claims a real transaction."""

    def __init__(self, instance_id, instance):
        self.instance_id = "0x" + instance_id
        self.instance = instance
        self.transitions = []
        self.requested = []

    def get_instance(self, instance_id):
        self.requested.append(("getInstance", instance_id))
        if instance_id != self.instance_id:
            raise KeyError("wrong task")
        return self.instance

    def get_transition(self, instance_id, index):
        self.requested.append(("getTransition", instance_id, index))
        if instance_id != self.instance_id:
            raise KeyError("wrong task")
        return self.transitions[index]


class CommittedVerifierTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.store = ArtifactStore(temp.name)
        self.catalog = TrustedCatalog([
            CatalogEntry("history", "controlled", 1, "https://p/history", "0xpay", "history"),
            CatalogEntry("reputation", "controlled", 2, "https://p/reputation", "0xpay", "rep"),
            CatalogEntry("reputation-alt", "controlled", 2, "https://p/rep-alt", "0xpay", "rep"),
            CatalogEntry("forensics", "controlled", 6, "https://p/forensics", "0xpay", "forensics"),
        ])
        self.intent = Intent(
            "assess risk", 10, tuple(self.catalog._by_service), ("controlled",)
        )
        self.prepared = prepare_task_instance(
            intent=self.intent, evaluator=PolicyEvaluator(self.catalog), store=self.store
        )
        self.ledger = FakeLedger(
            self.prepared.instance_id,
            LedgerInstance(
                "0x" + self.prepared.intent_id,
                "0x" + self.prepared.model_id,
                "0x" + self.prepared.policy_id,
                TaskState.ACTIVE,
                0,
                "0xabc",
            ),
        )

    def append(self, service, reference, outcome="success", *, payment_amount=None, instance_id=None):
        action = self.catalog.resolve(ActionProposal(service))
        aid = self.store.put(action.as_artifact())
        payment = Payment(
            reference, "payer", action.provider,
            action.value if payment_amount is None else payment_amount,
            aid, "x402-v2", "eip155:84532",
        )
        evidence = Evidence(
            instance_id if instance_id is not None else self.prepared.instance_id,
            aid, json.dumps({"service": service}), outcome, reference,
        )
        pid = self.store.put(payment.as_artifact())
        eid = self.store.put(evidence.as_artifact())
        self.ledger.transitions.append(LedgerTransition(
            TaskState.ACTIVE, "0x" + aid, "0x" + pid, "0x" + eid, TaskState.ACTIVE
        ))
        self.ledger.instance = replace(
            self.ledger.instance, transition_count=len(self.ledger.transitions)
        )

    def report(self):
        return verify_committed_task(
            instance_id=self.prepared.instance_id, store=self.store, ledger=self.ledger
        )

    def test_valid_two_transition_history_passes_encoded_policy(self):
        self.append("history", "0xtx1", "insufficient")
        self.append("reputation", "0xtx2", "success")
        result = self.report()
        self.assertEqual((result.structural_consistency, result.admission_replay), ("pass", "pass"))
        self.assertTrue(result.recorded_policy_verified)
        self.assertEqual(result.settlement_check, "unverified")
        self.assertEqual(result.transition_count, 2)
        self.assertEqual(result.settlement_refs, ["0xtx1", "0xtx2"])
        self.assertEqual(self.ledger.requested[0], ("getInstance", "0x" + self.prepared.instance_id))
        self.assertEqual(len([v for v in self.ledger.requested if v[0] == "getTransition"]), 2)

    def test_valid_history_with_terminal_finalization_passes(self):
        self.append("history", "0xtx1", "insufficient")
        self.ledger.instance = replace(self.ledger.instance, state=TaskState.COMPLETED)
        result = self.report()
        self.assertTrue(result.recorded_policy_verified)

    def test_redundant_purchase_structurally_valid_but_policy_denied(self):
        self.append("reputation", "0xtx1")
        self.append("reputation-alt", "0xtx2")
        result = self.report()
        self.assertEqual(result.structural_consistency, "pass")
        self.assertEqual(result.admission_replay, "fail")
        self.assertEqual(result.denied_transition, 1)
        self.assertIn("equivalent service already succeeded", " ".join(result.issues))
        self.assertFalse(result.recorded_policy_verified)

    def test_unaffordable_second_purchase_structurally_valid_policy_denied(self):
        self.append("forensics", "0xtx1", outcome="insufficient")
        self.append("forensics", "0xtx2", outcome="success")
        result = self.report()
        self.assertEqual(result.structural_consistency, "pass")
        self.assertEqual(result.admission_replay, "fail")
        self.assertEqual(result.denied_transition, 1)
        self.assertIn("budget", " ".join(result.issues))

    def test_unauthorized_provider_is_structurally_bound_but_policy_denied(self):
        self.append("history", "0xtx1")
        original = self.ledger.transitions[0]
        action = self.store.get(original.action_hash.removeprefix("0x"))
        action["provider"] = "unapproved-provider"
        action_id = self.store.put(action)
        payment = self.store.get(original.payment_hash.removeprefix("0x"))
        payment["payee"] = "unapproved-provider"
        payment["action_id"] = action_id
        payment_id = self.store.put(payment)
        evidence = self.store.get(original.evidence_hash.removeprefix("0x"))
        evidence["action_id"] = action_id
        evidence_id = self.store.put(evidence)
        self.ledger.transitions[0] = replace(
            original, action_hash="0x" + action_id,
            payment_hash="0x" + payment_id, evidence_hash="0x" + evidence_id,
        )
        report = self.report()
        self.assertEqual(report.structural_consistency, "pass")
        self.assertEqual(report.admission_replay, "fail")
        self.assertIn("provider is outside", " ".join(report.issues))

    def test_insufficient_first_equivalent_service_allows_fallback(self):
        self.append("reputation", "0xtx1", outcome="insufficient")
        self.append("reputation-alt", "0xtx2", outcome="success")
        self.assertTrue(self.report().recorded_policy_verified)

    def test_no_recorded_paid_actions_is_vacuously_admissible(self):
        result = self.report()
        self.assertEqual(result.transition_count, 0)
        self.assertTrue(result.recorded_policy_verified)
        self.assertEqual(result.settlement_check, "unverified")

    def test_missing_policy_artifact_is_unverified(self):
        (self.store.root / f"{self.prepared.policy_id}.json").unlink()
        result = self.report()
        self.assertEqual(result.structural_consistency, "unverified")
        self.assertEqual(result.admission_replay, "unverified")

    def test_tampered_policy_artifact_is_integrity_failure(self):
        path = self.store.root / f"{self.prepared.policy_id}.json"
        data = json.loads(path.read_text())
        data["catalog"][0]["value"] += 1
        path.write_text(json.dumps(data))
        result = self.report()
        self.assertEqual(result.structural_consistency, "fail")
        self.assertEqual(result.admission_replay, "unverified")

    def test_unknown_evaluator_version_yields_unverified_admission(self):
        snapshot = self.store.get(self.prepared.policy_id)
        snapshot["evaluator"]["implementation"] = "unknown.IndependentVerifier"
        self.ledger.instance = replace(
            self.ledger.instance, policy_hash="0x" + self.store.put(snapshot)
        )
        result = self.report()
        self.assertEqual(result.structural_consistency, "pass")
        self.assertEqual(result.admission_replay, "unverified")
        self.assertIn("unknown evaluator", " ".join(result.issues))

    def test_source_fingerprint_mismatch_yields_unverified_admission(self):
        snapshot = self.store.get(self.prepared.policy_id)
        snapshot["evaluator"]["source_sha256"]["policy.py"] = "0" * 64
        self.ledger.instance = replace(
            self.ledger.instance, policy_hash="0x" + self.store.put(snapshot)
        )
        result = self.report()
        self.assertEqual(result.structural_consistency, "pass")
        self.assertEqual(result.admission_replay, "unverified")
        self.assertIn("semantics", " ".join(result.issues))

    def test_artifact_data_mismatch_fails_before_replay(self):
        self.append("history", "0xtx1")
        path = self.store.root / (self.ledger.transitions[0].evidence_hash.removeprefix("0x") + ".json")
        obj = json.loads(path.read_text())
        obj["result"] += "changed"
        path.write_text(json.dumps(obj))
        result = self.report()
        self.assertEqual((result.structural_consistency, result.admission_replay), ("fail", "unverified"))

    def test_missing_transition_artifact_does_not_pass(self):
        self.append("history", "0xtx1")
        path = self.store.root / (self.ledger.transitions[0].payment_hash.removeprefix("0x") + ".json")
        path.unlink()
        result = self.report()
        self.assertEqual((result.structural_consistency, result.admission_replay), ("unverified", "unverified"))

    def test_cross_object_bindings_detect_other_task_evidence(self):
        self.append("history", "0xtx1", instance_id="elsewhere")
        result = self.report()
        self.assertEqual((result.structural_consistency, result.admission_replay), ("fail", "unverified"))
        self.assertIn("instance_id mismatch", " ".join(result.issues))

    def test_duplicate_settlement_reference_fails_structural(self):
        self.append("history", "0xtx1", outcome="insufficient")
        self.append("reputation", "0xtx1", outcome="success")
        result = self.report()
        self.assertEqual((result.structural_consistency, result.admission_replay), ("fail", "unverified"))

    def test_same_evm_settlement_in_different_case_is_reused(self):
        ref = "0x" + "aB" * 32
        self.append("history", ref, outcome="insufficient")
        self.append("reputation", ref.lower(), outcome="success")
        report = self.report()
        self.assertEqual(report.structural_consistency, "fail")
        self.assertIn("reused settlement", " ".join(report.issues))

    def test_empty_settlement_reference_not_accepted(self):
        self.append("history", "")
        result = self.report()
        self.assertEqual(result.structural_consistency, "fail")
        self.assertEqual(result.settlement_check, "unverified")

    def test_reject_fake_previous_state(self):
        self.append("history", "0xtx1")
        original = self.ledger.transitions[0]
        self.ledger.transitions[0] = replace(original, previous_state=TaskState.COMPLETED)
        result = self.report()
        self.assertEqual(result.structural_consistency, "fail")
        self.assertEqual(result.admission_replay, "unverified")

    def test_policy_hash_must_come_from_ledger_not_local_task_index(self):
        self.append("history", "0xtx1")
        self.ledger.instance = replace(self.ledger.instance, policy_hash="0x" + "11" * 32)
        result = self.report()
        self.assertEqual(result.structural_consistency, "unverified")
        self.assertEqual(result.admission_replay, "unverified")

    def test_no_onchain_instance_never_passes(self):
        self.ledger.instance_id = "0x" + "ff" * 32
        result = self.report()
        self.assertEqual(result.structural_consistency, "unverified")
        self.assertFalse(result.recorded_policy_verified)

    def test_malformed_intent_schema_is_rejected(self):
        intent = self.store.get(self.prepared.intent_id)
        intent["budget"] = True
        self.ledger.instance = replace(
            self.ledger.instance, intent_hash="0x" + self.store.put(intent)
        )
        result = self.report()
        self.assertEqual((result.structural_consistency, result.admission_replay), ("fail", "unverified"))

    def test_reader_decodes_contract_abi_without_live_rpc(self):
        calls = []
        class GetInstance:
            def __call__(self, raw):
                assert len(raw) == 32
                def call(*, block_identifier):
                    calls.append(("instance", block_identifier))
                    return (
                        bytes.fromhex("aa" * 32), bytes.fromhex("bb" * 32),
                        bytes.fromhex("cc" * 32), 3, 2, "0xabc"
                    )
                return SimpleNamespace(call=call)

        class GetTransition:
            def __call__(self, raw, index):
                assert len(raw) == 32 and index == 1
                def call(*, block_identifier):
                    calls.append(("transition", block_identifier))
                    return (
                        1, bytes.fromhex("11" * 32), bytes.fromhex("22" * 32),
                        bytes.fromhex("33" * 32), 1
                    )
                return SimpleNamespace(call=call)

        reader = object.__new__(Web3TaskReader)
        reader.block_number = 13579
        reader.contract = SimpleNamespace(functions=SimpleNamespace(
            getInstance=GetInstance(), getTransition=GetTransition()
        ))
        instance_id = "0x" + self.prepared.instance_id
        parsed = reader.get_instance(instance_id)
        self.assertEqual(parsed.state, TaskState.FAILED)
        self.assertEqual(parsed.transition_count, 2)
        transition = reader.get_transition(instance_id, 1)
        self.assertEqual(transition.action_hash, "0x" + "11" * 32)
        self.assertEqual(transition.previous_state, TaskState.ACTIVE)
        self.assertEqual(calls, [("instance", 13579), ("transition", 13579)])


if __name__ == "__main__":
    unittest.main()
