"""Step 4: construct and check an explicitly simulated redundant-purchase history.

This is an *adversarial record-commitment experiment*, NOT an x402 payment
experiment. Payment and provider evidence are synthetic, and successful
settlement must remain UNVERIFIED in every report. No production controller's
admission logic is bypassed or changed; only an explicitly controlled test
recorder can append the invalid second transition to LifecycleTracker.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Callable, Protocol

from .artifact_store import ArtifactStore
from .canonical import content_id
from .committed_verifier import (
    LedgerInstance, LedgerTransition, RecordedTaskVerificationReport,
    TaskLedgerReader, verify_committed_task,
)
from .model import ActionProposal, AcceptedTransition, Evidence, Intent, Payment, TaskState
from .policy import Decision, PolicyEvaluator
from .task_creation import PreparedTaskInstance, prepare_task_instance, register_task_instance


class ExperimentError(RuntimeError):
    """The experiment did not establish its expected limited verification property."""


@dataclass(frozen=True)
class PreparedExperimentTransition:
    service: str
    action_hash: str
    payment_hash: str
    evidence_hash: str
    synthetic_settlement_reference: str

    def as_dict(self) -> dict[str, str]:
        return {
            "service": self.service,
            "action_hash": "0x" + self.action_hash,
            "payment_hash": "0x" + self.payment_hash,
            "evidence_hash": "0x" + self.evidence_hash,
            "synthetic_settlement_reference": self.synthetic_settlement_reference,
        }


@dataclass(frozen=True)
class PreparedAdversarialExperiment:
    prepared: PreparedTaskInstance
    transitions: tuple[PreparedExperimentTransition, PreparedExperimentTransition]


class ExperimentLedgerRecorder(Protocol):
    def create_instance(
        self, *, instance_id: str, intent_hash: str, model_hash: str, policy_hash: str
    ) -> str: ...

    def record_transition(
        self, *, instance_id: str, expected_index: int,
        action_hash: str, payment_hash: str, evidence_hash: str,
    ) -> str: ...


def prepare_adversarial_experiment(
    *, intent: Intent, evaluator: PolicyEvaluator, store: ArtifactStore,
    first_service: str = "reputation", second_service: str = "reputation-alt",
) -> PreparedAdversarialExperiment:
    """Prepare unique hashes for a structurally bound but replay-invalid second action.

    Both actions MUST individually match the trusted catalog and delegated
    provider/service/budget constraints. The second denial must be caused by
    the prior success / equivalence rule, not another constraint.
    """
    first = evaluator.catalog.entry(first_service)
    second = evaluator.catalog.entry(second_service)
    if first.service == second.service:
        raise ValueError("use distinct services with one equivalence group")
    if (first.equivalence_group or first.service) != (second.equivalence_group or second.service):
        raise ValueError("services must be in the same policy equivalence group")
    if first.value + second.value > intent.budget:
        raise ValueError("budget must cover both actions: invalidity must be only history-dependent")

    prepared = prepare_task_instance(intent=intent, evaluator=evaluator, store=store)
    actions = [
        evaluator.catalog.resolve(ActionProposal(service))
        for service in (first_service, second_service)
    ]
    first_decision, first_reason = evaluator.evaluate(intent, TaskState.ACTIVE, [], actions[0])
    if first_decision != Decision.PERMIT:
        raise ValueError(f"first Action must be admissible: {first_reason}")

    bound: list[AcceptedTransition] = []
    entries: list[PreparedExperimentTransition] = []
    for index, action in enumerate(actions):
        action_hash = store.put(action.as_artifact())
        # Not an EVM transaction hash, deliberately cannot be mistaken for one.
        reference = f"SIMULATED-NO-SETTLEMENT:{prepared.instance_id}:{index}"
        payment = Payment(
            reference=reference,
            payer="no-token-transfer-experiment",
            payee=action.provider,
            amount=action.value,
            action_id=action_hash,
            protocol="simulation-no-x402",
            network="none",
        )
        evidence = Evidence(
            instance_id=prepared.instance_id,
            action_id=action_hash,
            result="SIMULATED: controller-asserted success; no provider attestation",
            outcome="success",
            receipt_ref=reference,
        )
        payment_hash = store.put(payment.as_artifact())
        evidence_hash = store.put(evidence.as_artifact())
        for h, obj in ((action_hash, action), (payment_hash, payment), (evidence_hash, evidence)):
            if content_id(obj.as_artifact()) != h or content_id(store.get(h)) != h:
                raise ExperimentError("stored artifact does not match its commitment")
        entries.append(PreparedExperimentTransition(
            service=action.service,
            action_hash=action_hash,
            payment_hash=payment_hash,
            evidence_hash=evidence_hash,
            synthetic_settlement_reference=reference,
        ))
        bound.append(AcceptedTransition(action, payment, evidence))

    second_decision, second_reason = evaluator.evaluate(
        intent, TaskState.ACTIVE, bound[:1], actions[1]
    )
    if second_decision != Decision.DENY or second_reason != "equivalent service already succeeded":
        raise ValueError(f"second Action must be denied ONLY for prior success: {second_reason}")
    return PreparedAdversarialExperiment(prepared, (entries[0], entries[1]))


class SimulatedTaskLedger:
    """Explicitly OFF-CHAIN fake ledger for unit tests and default dry-run."""

    def __init__(self, experiment: PreparedAdversarialExperiment):
        self._instance_id = "0x" + experiment.prepared.instance_id
        self._instance = LedgerInstance(
            "0x" + experiment.prepared.intent_id,
            "0x" + experiment.prepared.model_id,
            "0x" + experiment.prepared.policy_id,
            TaskState.ACTIVE, 0, "simulation-not-an-evm-address",
        )
        self._records: list[LedgerTransition] = []

    def append(self, transition: PreparedExperimentTransition) -> None:
        self._records.append(LedgerTransition(
            TaskState.ACTIVE,
            "0x" + transition.action_hash,
            "0x" + transition.payment_hash,
            "0x" + transition.evidence_hash,
            TaskState.ACTIVE,
        ))
        self._instance = replace(self._instance, transition_count=len(self._records))

    def get_instance(self, instance_id: str) -> LedgerInstance:
        if instance_id != self._instance_id:
            raise KeyError("unknown simulated instance")
        return self._instance

    def get_transition(self, instance_id: str, index: int) -> LedgerTransition:
        if instance_id != self._instance_id:
            raise KeyError("unknown simulated instance")
        return self._records[index]


def assert_experiment_reports(
    after_first: RecordedTaskVerificationReport,
    after_second: RecordedTaskVerificationReport,
) -> None:
    """Fail closed if the purported counterexample does not demonstrate its claim."""
    if (after_first.structural_consistency, after_first.admission_replay,
        after_first.transition_count, after_first.settlement_check) != (
        "pass", "pass", 1, "unverified"
    ):
        raise ExperimentError("valid first transition did not pass recorded-policy verification")
    if (after_second.structural_consistency, after_second.admission_replay,
        after_second.transition_count, after_second.denied_transition,
        after_second.settlement_check) != (
        "pass", "fail", 2, 1, "unverified"
    ):
        raise ExperimentError(
            "counterexample must have structural PASS, admission FAIL at index 1, "
            "and settlement UNVERIFIED"
        )
    if not any("equivalent service already succeeded" in issue for issue in after_second.issues):
        raise ExperimentError("negative result must be caused by prior-success rule")


def run_offline_experiment(
    *, experiment: PreparedAdversarialExperiment, store: ArtifactStore,
) -> dict:
    """Zero network interactions; labels all results as simulated ledger data."""
    ledger = SimulatedTaskLedger(experiment)
    ledger.append(experiment.transitions[0])
    first = verify_committed_task(
        instance_id=experiment.prepared.instance_id, store=store, ledger=ledger
    )
    ledger.append(experiment.transitions[1])
    second = verify_committed_task(
        instance_id=experiment.prepared.instance_id, store=store, ledger=ledger
    )
    assert_experiment_reports(first, second)
    return {
        "schema": "admission-replay-experiment/v1",
        "mode": "offline-simulated-ledger",
        "onchain_lifecycle_commitments": False,
        "provider_attested": False,
        "actual_payments": False,
        "settlement_check": "unverified",
        "instance_id": "0x" + experiment.prepared.instance_id,
        "intent_hash": "0x" + experiment.prepared.intent_id,
        "model_hash": "0x" + experiment.prepared.model_id,
        "policy_hash": "0x" + experiment.prepared.policy_id,
        "transitions": [transition.as_dict() for transition in experiment.transitions],
        "after_first": first.as_dict(),
        "after_second": second.as_dict(),
        "claim": "Simulated recorded history: structural pass, admission replay fail",
    }


def run_onchain_experiment(
    *, experiment: PreparedAdversarialExperiment, intent: Intent,
    store: ArtifactStore, recorder: ExperimentLedgerRecorder,
    reader_factory: Callable[[], TaskLedgerReader],
    on_event: Callable[[str, dict], None] | None = None,
) -> dict:
    """Record 3 *lifecycle* testnet transactions, never actual x402 payments.

    A callback permits the CLI to persist a durable progress journal before and
    after individual transmissions. Any ambiguous submission must be reconciled
    against the chain; there is NO automatic retry or rollback.
    """
    def event(name: str, values: dict) -> None:
        if on_event is not None:
            on_event(name, values)

    p = experiment.prepared
    event("before_create", {"instance_id": "0x" + p.instance_id})
    created = register_task_instance(
        prepared=p, intent=intent, store=store, recorder=recorder
    )
    event("created", {"creation_tx": created.transaction_hash})
    hashes: list[str] = []
    reports: list[RecordedTaskVerificationReport] = []
    for index, entry in enumerate(experiment.transitions):
        event("before_record", {"transition_index": index, "commitments": entry.as_dict()})
        receipt_tx_hash = recorder.record_transition(
            instance_id="0x" + p.instance_id,
            expected_index=index,
            action_hash="0x" + entry.action_hash,
            payment_hash="0x" + entry.payment_hash,
            evidence_hash="0x" + entry.evidence_hash,
        )
        hashes.append(receipt_tx_hash)
        event("recorded", {"transition_index": index, "recording_tx": receipt_tx_hash})
        # Create a fresh reader AFTER the tx, so the pinned block includes it.
        report = verify_committed_task(
            instance_id=p.instance_id, store=store, ledger=reader_factory()
        )
        reports.append(report)
        event("verified", {"transition_index": index, "verification": report.as_dict()})
        if index == 0 and not report.recorded_policy_verified:
            raise ExperimentError("first on-chain transition failed recorded-policy verification")
        if index == 1:
            assert_experiment_reports(reports[0], reports[1])

    return {
        "schema": "admission-replay-experiment/v1",
        "mode": "onchain-ledger-with-simulated-payments",
        "onchain_lifecycle_commitments": True,
        "provider_attested": False,
        "actual_payments": False,
        "settlement_check": "unverified",
        "instance_id": "0x" + p.instance_id,
        "intent_hash": "0x" + p.intent_id,
        "model_hash": "0x" + p.model_id,
        "policy_hash": "0x" + p.policy_id,
        "creation_tx": created.transaction_hash,
        "recording_txs": hashes,
        "transitions": [transition.as_dict() for transition in experiment.transitions],
        "after_first": reports[0].as_dict(),
        "after_second": reports[1].as_dict(),
        "claim": "Committed on-chain history: structural pass, admission replay fail; no paid settlement proof",
    }
