"""Step 2: deterministic creation, persistence, and registration tests."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from verifiable_task_lifecycles.artifact_store import ArtifactStore
from verifiable_task_lifecycles.canonical import content_id
from verifiable_task_lifecycles.model import Action, Intent, TaskState
from verifiable_task_lifecycles.policy import CatalogEntry, Decision, PolicyEvaluator, TrustedCatalog
from verifiable_task_lifecycles.policy_snapshot import load_committed_policy
from verifiable_task_lifecycles.task_creation import (
    TaskCreationError, create_task_instance, prepare_task_instance,
    register_task_instance,
)


class FakeLedger:
    def __init__(self, failure=False):
        self.calls = []
        self.failure = failure

    def create_instance(self, **kwargs):
        self.calls.append(kwargs)
        if self.failure:
            raise TaskCreationError("simulated reverted transaction")
        return "0x" + "ab" * 32


class TaskCreationTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.store = ArtifactStore(self.tempdir.name)
        self.catalog = TrustedCatalog([
            CatalogEntry("history", "vendor-a", 1, "https://a.example", "0x01", "history"),
            CatalogEntry("reputation", "vendor-b", 2, "https://b.example", "0x02", "rep"),
        ])
        self.evaluator = PolicyEvaluator(self.catalog)
        self.intent = Intent("Assess X", 10, ("history", "reputation"), ("vendor-a", "vendor-b"))
        self.ledger = FakeLedger()

    def prepare(self, **kwargs):
        return prepare_task_instance(
            intent=self.intent, evaluator=self.evaluator, store=self.store, **kwargs
        )

    def test_preparation_persists_policy_intent_and_lifecycle_model(self):
        prepared = self.prepare()
        self.assertEqual(len(prepared.instance_id), 64)
        self.assertEqual(self.store.get(prepared.intent_id), self.intent.as_artifact())
        self.assertEqual(self.store.get(prepared.model_id)["initial_state"], "active")
        policy = self.store.get(prepared.policy_id)
        self.assertEqual(content_id(policy), prepared.policy_id)
        self.assertEqual(prepared.contract_arguments["policy_hash"], "0x" + prepared.policy_id)
        evaluator = load_committed_policy(policy, expected_commitment=prepared.contract_arguments["policy_hash"])
        action = Action("purchase_service", "vendor-a", "history", {}, 1)
        self.assertEqual(evaluator.evaluate(self.intent, TaskState.ACTIVE, [], action)[0], Decision.PERMIT)
        self.assertFalse(list(Path(self.tempdir.name).rglob("instances/*.json")))

    def test_creation_submits_exact_persisted_commitments_and_indexes_success(self):
        created = create_task_instance(
            intent=self.intent, evaluator=self.evaluator, store=self.store, recorder=self.ledger
        )
        prepared = created.prepared
        self.assertEqual(self.ledger.calls, [prepared.contract_arguments])
        self.assertEqual(created.context.instance_id, prepared.instance_id)
        self.assertEqual(created.context.intent, self.intent)
        self.assertEqual(created.context.state, TaskState.ACTIVE)
        index = json.loads(created.manifest_path.read_text())
        self.assertEqual(index["creation_tx"], created.transaction_hash)
        self.assertEqual(index["policy_id"], prepared.policy_id)
        self.assertEqual(index["intent_id"], prepared.intent_id)
        self.assertEqual(index["model_id"], prepared.model_id)
        self.assertEqual(self.store.get(prepared.policy_id)["schema"], "verifiable-task-policy-snapshot/v1")

    def test_instances_have_distinct_ids_but_same_policy_commitment(self):
        one = self.prepare()
        two = self.prepare()
        self.assertNotEqual(one.instance_id, two.instance_id)
        self.assertEqual(one.intent_id, two.intent_id)
        self.assertEqual(one.model_id, two.model_id)
        self.assertEqual(one.policy_id, two.policy_id)

    def test_registration_failure_does_not_create_success_manifest(self):
        prepared = self.prepare()
        ledger = FakeLedger(failure=True)
        with self.assertRaises(TaskCreationError):
            register_task_instance(
                prepared=prepared, intent=self.intent, store=self.store, recorder=ledger
            )
        self.assertEqual(len(ledger.calls), 1)
        self.assertFalse((self.store.root / "instances" / f"{prepared.instance_id}.json").exists())
        self.assertEqual(self.store.get(prepared.policy_id)["schema"], "verifiable-task-policy-snapshot/v1")

    def test_tampered_policy_prevents_registration(self):
        prepared = self.prepare()
        policy_path = self.store.root / f"{prepared.policy_id}.json"
        snapshot = self.store.get(prepared.policy_id)
        snapshot["catalog"][0]["value"] += 10
        policy_path.write_text(json.dumps(snapshot))
        with self.assertRaises(TaskCreationError):
            register_task_instance(
                prepared=prepared, intent=self.intent, store=self.store, recorder=self.ledger
            )
        self.assertFalse(self.ledger.calls)

    def test_swapped_intent_prevents_registration(self):
        prepared = self.prepare()
        other = Intent("Assess Y", 10, self.intent.allowed_services, self.intent.allowed_providers)
        with self.assertRaises(TaskCreationError):
            register_task_instance(
                prepared=prepared, intent=other, store=self.store, recorder=self.ledger
            )
        self.assertFalse(self.ledger.calls)

    def test_bad_instance_id_rejected_before_persisting(self):
        with self.assertRaises(ValueError):
            self.prepare(instance_id="bad-id")
        with self.assertRaises(ValueError):
            self.prepare(instance_id="0x" + "00" * 32)
        self.assertFalse(list(self.store.root.glob("*.json")))

    def test_duplicate_local_manifest_rejected_before_ledger(self):
        prepared = self.prepare(instance_id="fa" * 32)
        first = register_task_instance(
            prepared=prepared, intent=self.intent, store=self.store, recorder=self.ledger
        )
        self.assertTrue(first.manifest_path.exists())
        with self.assertRaises(TaskCreationError):
            register_task_instance(
                prepared=prepared, intent=self.intent, store=self.store, recorder=self.ledger
            )
        self.assertEqual(len(self.ledger.calls), 1)

    def test_bad_artifact_store_rejected_before_ledger(self):
        class BrokenStore(ArtifactStore):
            def put(self, value):
                return "0" * 64

        bad_store = BrokenStore(self.tempdir.name)
        with self.assertRaises(TaskCreationError):
            prepare_task_instance(
                intent=self.intent, evaluator=self.evaluator, store=bad_store
            )
        self.assertFalse(self.ledger.calls)

    def test_unsupported_lifecycle_model_rejected_before_recording(self):
        with self.assertRaises(ValueError):
            self.prepare(lifecycle_model={"schema": "unsupported"})
        self.assertFalse(self.ledger.calls)

    def test_invalid_ledger_confirmation_never_creates_manifest(self):
        class InvalidConfirmation(FakeLedger):
            def create_instance(self, **kwargs):
                self.calls.append(kwargs)
                return "pending"

        prepared = self.prepare()
        with self.assertRaises(TaskCreationError):
            register_task_instance(
                prepared=prepared, intent=self.intent, store=self.store,
                recorder=InvalidConfirmation(),
            )
        self.assertFalse((self.store.root / "instances" / f"{prepared.instance_id}.json").exists())


if __name__ == "__main__":
    unittest.main()
