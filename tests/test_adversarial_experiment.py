"""Step 4: distinguish actual chain commitments from simulated payments."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from verifiable_task_lifecycles.adversarial_experiment import (
    ExperimentError, SimulatedTaskLedger, assert_experiment_reports,
    prepare_adversarial_experiment, run_offline_experiment, run_onchain_experiment,
)
from verifiable_task_lifecycles.artifact_store import ArtifactStore
from verifiable_task_lifecycles.committed_verifier import LedgerTransition, verify_committed_task
from verifiable_task_lifecycles.model import Intent, TaskState
from verifiable_task_lifecycles.policy import CatalogEntry, PolicyEvaluator, TrustedCatalog


class FakeOnchainRecorder:
    """Simulates the contract's state; never signs a transaction."""
    def __init__(self, experiment, *, fail_index=None):
        self.experiment = experiment
        self.fail_index = fail_index
        self.ledger = SimulatedTaskLedger(experiment)
        self.created = False
        self.recorded = []

    def create_instance(self, *, instance_id, intent_hash, model_hash, policy_hash):
        assert instance_id == "0x" + self.experiment.prepared.instance_id
        assert intent_hash == "0x" + self.experiment.prepared.intent_id
        assert model_hash == "0x" + self.experiment.prepared.model_id
        assert policy_hash == "0x" + self.experiment.prepared.policy_id
        self.created = True
        return "0x" + "aa" * 32

    def record_transition(self, *, instance_id, expected_index,
                          action_hash, payment_hash, evidence_hash):
        assert self.created
        assert instance_id == "0x" + self.experiment.prepared.instance_id
        assert len(self.recorded) == expected_index
        entry = self.experiment.transitions[expected_index]
        assert (action_hash, payment_hash, evidence_hash) == (
            "0x" + entry.action_hash, "0x" + entry.payment_hash,
            "0x" + entry.evidence_hash,
        )
        if expected_index == self.fail_index:
            raise RuntimeError("simulated transport failure; tx status unknown")
        self.ledger.append(entry)
        self.recorded.append(expected_index)
        return "0x" + format(expected_index + 1, "064x")


class AdversarialExperimentTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.store = ArtifactStore(temp.name)
        self.catalog = TrustedCatalog([
            CatalogEntry("reputation", "provider", 2, "https://example.invalid/rep", "0xtest", "rep"),
            CatalogEntry("reputation-alt", "provider", 2, "https://example.invalid/rep2", "0xtest", "rep"),
            CatalogEntry("history", "provider", 1, "https://example.invalid/history", "0xtest", "history"),
        ])
        self.intent = Intent("controlled probe", 10, ("reputation", "reputation-alt", "history"), ("provider",))
        self.evaluator = PolicyEvaluator(self.catalog)
        self.experiment = self.prepare()

    def prepare(self):
        return prepare_adversarial_experiment(
            intent=self.intent, evaluator=self.evaluator, store=self.store
        )

    def test_offline_prefix_passes_and_recorded_redundancy_fails_admission(self):
        report = run_offline_experiment(experiment=self.experiment, store=self.store)
        self.assertEqual(report["mode"], "offline-simulated-ledger")
        self.assertFalse(report["onchain_lifecycle_commitments"])
        self.assertFalse(report["actual_payments"])
        self.assertEqual(report["settlement_check"], "unverified")
        self.assertEqual((report["after_first"]["structural_consistency"],
                          report["after_first"]["admission_replay"]), ("pass", "pass"))
        self.assertEqual((report["after_second"]["structural_consistency"],
                          report["after_second"]["admission_replay"]), ("pass", "fail"))
        self.assertEqual(report["after_second"]["denied_transition"], 1)
        self.assertIn("equivalent service already succeeded", str(report["after_second"]["issues"]))
        self.assertTrue(all(
            row["synthetic_settlement_reference"].startswith("SIMULATED-NO-SETTLEMENT:")
            for row in report["transitions"]
        ))

    def test_same_service_rejected_at_preparation(self):
        with self.assertRaisesRegex(ValueError, "distinct services"):
            prepare_adversarial_experiment(
                intent=self.intent, evaluator=self.evaluator, store=self.store,
                first_service="reputation", second_service="reputation",
            )

    def test_non_equivalent_services_rejected_at_preparation(self):
        with self.assertRaisesRegex(ValueError, "same policy equivalence"):
            prepare_adversarial_experiment(
                intent=self.intent, evaluator=self.evaluator, store=self.store,
                first_service="reputation", second_service="history",
            )

    def test_budget_confounded_scenario_rejected(self):
        short_intent = Intent("probe", 3, self.intent.allowed_services, self.intent.allowed_providers)
        with self.assertRaisesRegex(ValueError, "budget must cover"):
            prepare_adversarial_experiment(
                intent=short_intent, evaluator=self.evaluator, store=self.store
            )

    def test_first_action_outside_intent_fails(self):
        changed_intent = Intent("probe", 10, ("reputation-alt",), ("provider",))
        with self.assertRaisesRegex(ValueError, "first Action must be admissible"):
            prepare_adversarial_experiment(
                intent=changed_intent, evaluator=self.evaluator, store=self.store
            )

    def test_tampered_committed_artifact_does_not_demonstrate_counterexample(self):
        entry = self.experiment.transitions[1]
        path = self.store.root / (entry.evidence_hash + ".json")
        path.write_text(json.dumps({"tampered": True}), encoding="utf-8")
        with self.assertRaises(ExperimentError):
            run_offline_experiment(experiment=self.experiment, store=self.store)

    def test_mocked_contract_workflow_success_with_fresh_verifier_each_step(self):
        fake = FakeOnchainRecorder(self.experiment)
        events = []
        result = run_onchain_experiment(
            experiment=self.experiment, intent=self.intent, store=self.store,
            recorder=fake, reader_factory=lambda: fake.ledger,
            on_event=lambda event, data: events.append((event, data)),
        )
        self.assertEqual(fake.recorded, [0, 1])
        self.assertEqual(result["mode"], "onchain-ledger-with-simulated-payments")
        self.assertFalse(result["actual_payments"])
        self.assertEqual(result["after_first"]["admission_replay"], "pass")
        self.assertEqual(result["after_second"]["admission_replay"], "fail")
        self.assertEqual([name for name, _ in events], [
            "before_create", "created", "before_record", "recorded", "verified",
            "before_record", "recorded", "verified",
        ])

    def test_mocked_failure_after_first_is_not_retried(self):
        fake = FakeOnchainRecorder(self.experiment, fail_index=1)
        events = []
        with self.assertRaisesRegex(RuntimeError, "status unknown"):
            run_onchain_experiment(
                experiment=self.experiment, intent=self.intent, store=self.store,
                recorder=fake, reader_factory=lambda: fake.ledger,
                on_event=lambda event, data: events.append(event),
            )
        self.assertEqual(fake.recorded, [0])
        self.assertEqual(events[-1], "before_record")

    def test_cli_offline_writes_a_report_without_web3_or_private_key(self):
        report = self.store.root / "result.json"
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts/run_adversarial_replay.py"),
             "--store", str(self.store.root / "store"), "--report", str(report)],
            capture_output=True, text=True, cwd=ROOT,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(report.read_text())["after_second"]["admission_replay"], "fail")
        proc2 = subprocess.run(
            [sys.executable, str(ROOT / "scripts/run_adversarial_replay.py"),
             "--store", str(self.store.root / "store"), "--report", str(report)],
            capture_output=True, text=True, cwd=ROOT,
        )
        self.assertNotEqual(proc2.returncode, 0, "should not overwrite an existing report")

    def test_cli_send_must_acknowledge_synthetic_payments(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/run_adversarial_replay.py"), "--send"],
            capture_output=True, text=True, cwd=ROOT,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--acknowledge-synthetic-payments", result.stderr)


if __name__ == "__main__":
    unittest.main()
