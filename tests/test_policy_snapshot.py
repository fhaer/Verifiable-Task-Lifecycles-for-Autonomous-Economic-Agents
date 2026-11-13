"""Standalone standard-library tests for committed deterministic policy inputs."""

import copy
import unittest

from verifiable_task_lifecycles.model import Action, Intent, TaskState
from verifiable_task_lifecycles.policy import CatalogEntry, Decision, TrustedCatalog
from verifiable_task_lifecycles.policy_snapshot import (
    InvalidPolicySnapshot,
    PolicyCommitmentMismatch,
    UnsupportedPolicySnapshot,
    export_policy_snapshot,
    load_committed_policy,
    policy_commitment,
)


class PolicySnapshotTests(unittest.TestCase):
    def setUp(self):
        self.catalog = TrustedCatalog([
            CatalogEntry("reputation", "vendor-b", 2, "https://b.example", "0xabc", "rep"),
            CatalogEntry("history", "vendor-a", 1, "https://a.example", "0xdef", "history"),
        ])
        self.snapshot = export_policy_snapshot(self.catalog)
        self.digest = policy_commitment(self.snapshot)

    def test_reproducible_commitment_independent_of_catalog_input_order(self):
        other = TrustedCatalog(list(reversed(list(self.catalog._by_service.values()))))
        self.assertEqual(self.snapshot, export_policy_snapshot(other))
        self.assertEqual(self.digest, policy_commitment(export_policy_snapshot(other)))
        self.assertEqual(len(self.digest), 66)

    def test_snapshot_can_reconstruct_original_policy(self):
        evaluator = load_committed_policy(self.snapshot, expected_commitment=self.digest)
        intent = Intent("Inspect X", 10, ("history", "reputation"), ("vendor-a", "vendor-b"))
        action = Action("purchase_service", "vendor-a", "history", {}, 1)
        self.assertEqual(evaluator.evaluate(intent, TaskState.ACTIVE, [], action)[0], Decision.PERMIT)
        self.assertEqual(evaluator.evaluate(intent, TaskState.COMPLETED, [], action)[0], Decision.DENY)

    def test_missing_artifact_does_not_pass(self):
        with self.assertRaises(UnsupportedPolicySnapshot):
            load_committed_policy(None, expected_commitment=self.digest)

    def test_changed_catalog_fails_commitment(self):
        altered = copy.deepcopy(self.snapshot)
        altered["catalog"][0]["value"] += 1
        with self.assertRaises(PolicyCommitmentMismatch):
            load_committed_policy(altered, expected_commitment=self.digest)

    def test_unknown_implementation_remains_unverified(self):
        changed = copy.deepcopy(self.snapshot)
        changed["evaluator"]["implementation"] = "unknown implementation"
        with self.assertRaises(UnsupportedPolicySnapshot):
            load_committed_policy(changed, expected_commitment=policy_commitment(changed))

    def test_different_code_fingerprint_remains_unverified(self):
        changed = copy.deepcopy(self.snapshot)
        changed["evaluator"]["source_sha256"]["policy.py"] = "f" * 64
        with self.assertRaises(UnsupportedPolicySnapshot):
            load_committed_policy(changed, expected_commitment=policy_commitment(changed))

    def test_duplicate_service_cannot_be_replayed(self):
        changed = copy.deepcopy(self.snapshot)
        changed["catalog"].append(copy.deepcopy(changed["catalog"][0]))
        with self.assertRaises(InvalidPolicySnapshot):
            load_committed_policy(changed, expected_commitment=policy_commitment(changed))


if __name__ == "__main__":
    unittest.main()
