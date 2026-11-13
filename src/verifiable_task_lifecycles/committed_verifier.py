"""Read-only, commitment-backed replay of a recorded economic task.

The ledger reader supplies expected commitments from LifecycleTracker, not from
an exported controller bundle.  The off-chain store supplies only the content
of objects addressed by those commitments.  Admission replay establishes
compliance with the committed *encoded* policy and recorded history; it does
not authenticate principal consent, provider responses or omitted payments.

Settlement transaction receipts are deliberately not checked in this step:
the report exposes settlement_check='unverified' rather than implying they are.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from .artifact_store import ArtifactStore
from .canonical import content_id
from .model import Action, AcceptedTransition, Evidence, Intent, Payment, TaskState
from .policy import Decision
from .policy_snapshot import (
    InvalidPolicySnapshot,
    PolicyCommitmentMismatch,
    UnsupportedPolicySnapshot,
    load_committed_policy,
)
from .task_creation import DEFAULT_LIFECYCLE_MODEL

CheckStatus = Literal["pass", "fail", "unverified"]
_HEX32 = re.compile(r"(?:0x)?[0-9a-fA-F]{64}\Z")
_MAX_TRANSITIONS = 10000


@dataclass(frozen=True)
class LedgerInstance:
    """Decoded LifecycleTracker.getInstance() response."""

    intent_hash: str
    model_hash: str
    policy_hash: str
    state: TaskState
    transition_count: int
    creator: str


@dataclass(frozen=True)
class LedgerTransition:
    """Decoded LifecycleTracker.getTransition() response."""

    previous_state: TaskState
    action_hash: str
    payment_hash: str
    evidence_hash: str
    next_state: TaskState


class TaskLedgerReader(Protocol):
    """Trusted read interface bound to the intended chain and contract."""

    def get_instance(self, instance_id: str) -> LedgerInstance: ...

    def get_transition(self, instance_id: str, index: int) -> LedgerTransition: ...


@dataclass
class RecordedTaskVerificationReport:
    instance_id: str
    structural_consistency: CheckStatus = "unverified"
    admission_replay: CheckStatus = "unverified"
    settlement_check: CheckStatus = "unverified"
    transition_count: int = 0
    issues: list[str] = field(default_factory=list)
    settlement_refs: list[str] = field(default_factory=list)
    denied_transition: int | None = None

    @property
    def recorded_policy_verified(self) -> bool:
        """Does NOT imply independent settlement or provider authentication."""
        return self.structural_consistency == "pass" and self.admission_replay == "pass"

    def as_dict(self) -> dict[str, Any]:
        return {
            "instance_id": self.instance_id,
            "structural_consistency": self.structural_consistency,
            "admission_replay": self.admission_replay,
            "settlement_check": self.settlement_check,
            "recorded_policy_verified": self.recorded_policy_verified,
            "transition_count": self.transition_count,
            "denied_transition": self.denied_transition,
            "issues": list(self.issues),
            "settlement_refs": list(self.settlement_refs),
        }


class _UnavailableArtifact(Exception):
    pass


class _IncorrectArtifact(Exception):
    pass


def _digest(value: str, label: str) -> str:
    if not isinstance(value, str) or _HEX32.fullmatch(value) is None:
        raise _IncorrectArtifact(f"{label} is not a SHA-256 bytes32 commitment")
    return value.lower().removeprefix("0x")


def _settlement_key(reference: str) -> str:
    # EVM transaction hashes are case-insensitive hex values; do not allow
    # the same settlement to be reused with different letter casing.
    if re.fullmatch(r"0x[0-9a-fA-F]{64}", reference):
        return reference.lower()
    return reference


def _load(store: ArtifactStore, commitment: str, label: str) -> dict[str, Any]:
    identifier = _digest(commitment, label)
    try:
        obj = store.get(identifier)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise _UnavailableArtifact(f"{label} artifact unavailable: {identifier}") from exc
    if content_id(obj) != identifier:
        raise _IncorrectArtifact(f"{label} artifact content does not match on-chain commitment")
    if not isinstance(obj, dict):
        raise _IncorrectArtifact(f"{label} artifact must be a JSON object")
    return obj


def _fields(obj: dict[str, Any], expected: set[str], label: str) -> None:
    if set(obj) != expected:
        raise _IncorrectArtifact(f"{label} artifact has unexpected or missing fields")


def _string(value: Any, field_name: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str):
        raise _IncorrectArtifact(f"{field_name} must be a string")
    return value


def _integer(value: Any, field_name: str) -> int:
    if type(value) is not int or value < 0:
        raise _IncorrectArtifact(f"{field_name} must be a nonnegative integer")
    return value


def _decode_intent(obj: dict[str, Any]) -> Intent:
    _fields(obj, {"goal", "budget", "allowed_services", "allowed_providers"}, "Intent")
    services = obj["allowed_services"]
    providers = obj["allowed_providers"]
    if not isinstance(services, list) or not all(isinstance(v, str) for v in services):
        raise _IncorrectArtifact("Intent.allowed_services must be a list of strings")
    if not isinstance(providers, list) or not all(isinstance(v, str) for v in providers):
        raise _IncorrectArtifact("Intent.allowed_providers must be a list of strings")
    return Intent(
        goal=_string(obj["goal"], "Intent.goal"),
        budget=_integer(obj["budget"], "Intent.budget"),
        allowed_services=tuple(services),
        allowed_providers=tuple(providers),
    )


def _decode_action(obj: dict[str, Any]) -> Action:
    _fields(obj, {"operation", "provider", "service", "parameters", "value"}, "Action")
    if not isinstance(obj["parameters"], dict):
        raise _IncorrectArtifact("Action.parameters must be an object")
    action = Action(
        operation=_string(obj["operation"], "Action.operation"),
        provider=_string(obj["provider"], "Action.provider"),
        service=_string(obj["service"], "Action.service"),
        parameters=obj["parameters"],
        value=_integer(obj["value"], "Action.value"),
    )
    if action.operation != "purchase_service":
        raise _IncorrectArtifact("unsupported Action operation")
    return action


def _decode_payment(obj: dict[str, Any]) -> Payment:
    _fields(obj, {"reference", "payer", "payee", "amount", "action_id", "protocol", "network"}, "Payment")
    return Payment(
        reference=_string(obj["reference"], "Payment.reference"),
        payer=_string(obj["payer"], "Payment.payer"),
        payee=_string(obj["payee"], "Payment.payee"),
        amount=_integer(obj["amount"], "Payment.amount"),
        action_id=_string(obj["action_id"], "Payment.action_id"),
        protocol=_string(obj["protocol"], "Payment.protocol"),
        network=_string(obj["network"], "Payment.network"),
    )


def _decode_evidence(obj: dict[str, Any]) -> Evidence:
    _fields(obj, {"instance_id", "action_id", "result", "outcome", "receipt_ref"}, "Evidence")
    return Evidence(
        instance_id=_string(obj["instance_id"], "Evidence.instance_id"),
        action_id=_string(obj["action_id"], "Evidence.action_id"),
        result=_string(obj["result"], "Evidence.result"),
        outcome=_string(obj["outcome"], "Evidence.outcome"),
        receipt_ref=_string(obj["receipt_ref"], "Evidence.receipt_ref", nullable=True),
    )


def _state(value: Any) -> TaskState:
    if isinstance(value, bool):
        raise _IncorrectArtifact("invalid lifecycle state")
    try:
        state = TaskState(value)
    except (ValueError, TypeError) as exc:
        raise _IncorrectArtifact("invalid lifecycle state") from exc
    if state == TaskState.NONE:
        raise _IncorrectArtifact("uninitialized lifecycle state")
    return state


def verify_committed_task(
    *, instance_id: str, store: ArtifactStore, ledger: TaskLedgerReader
) -> RecordedTaskVerificationReport:
    """Check a NEW task from independently read on-chain commitments.

    The ledger adapter must be tied to the intended chain/contract; a local
    manifest or controller-exported record is NOT an acceptable ledger source.
    In tests a fake reader stands in for the ledger, without claiming live RPC.

    Structural errors suppress admission replay. Policy replay failures remain
    distinguishable from structural failures. Receipt verification stays
    'unverified' until a separate independent settlement check is integrated.
    """
    report = RecordedTaskVerificationReport(instance_id=str(instance_id))
    try:
        normalized_instance = _digest(instance_id, "instance_id")
        if normalized_instance == "0" * 64:
            raise _IncorrectArtifact("instance_id must not be zero")
    except _IncorrectArtifact as exc:
        report.structural_consistency = "fail"
        report.issues.append(str(exc))
        return report

    report.instance_id = normalized_instance
    try:
        instance = ledger.get_instance("0x" + normalized_instance)
    except Exception as exc:
        report.issues.append(f"on-chain instance unavailable: {type(exc).__name__}: {exc}")
        return report

    try:
        final_state = _state(instance.state)
        n = _integer(instance.transition_count, "transition_count")
        if n > _MAX_TRANSITIONS:
            raise _IncorrectArtifact("transition count exceeds verifier safety limit")
        if not isinstance(instance.creator, str) or not instance.creator:
            raise _IncorrectArtifact("missing on-chain instance creator")
        # Commitments must be sourced from the reader, never from local index.
        intent_hash = _digest(instance.intent_hash, "intentHash")
        model_hash = _digest(instance.model_hash, "modelHash")
        policy_hash = _digest(instance.policy_hash, "policyHash")
        if any(h == "0" * 64 for h in (intent_hash, model_hash, policy_hash)):
            raise _IncorrectArtifact("zero on-chain task commitment")
        report.transition_count = n
    except (AttributeError, _IncorrectArtifact) as exc:
        report.structural_consistency = "fail"
        report.issues.append(str(exc))
        return report

    try:
        intent = _decode_intent(_load(store, intent_hash, "Intent"))
        lifecycle_model = _load(store, model_hash, "lifecycle model")
        if lifecycle_model != DEFAULT_LIFECYCLE_MODEL:
            raise _IncorrectArtifact("unsupported or mismatching committed lifecycle model")
        snapshot = _load(store, policy_hash, "policy")
    except _UnavailableArtifact as exc:
        report.issues.append(str(exc))
        return report
    except _IncorrectArtifact as exc:
        report.structural_consistency = "fail"
        report.issues.append(str(exc))
        return report

    policy_issue: str | None = None
    evaluator = None
    try:
        evaluator = load_committed_policy(snapshot, expected_commitment="0x" + policy_hash)
    except PolicyCommitmentMismatch as exc:
        report.structural_consistency = "fail"
        report.issues.append(f"policy commitment mismatch: {exc}")
        return report
    except (UnsupportedPolicySnapshot, InvalidPolicySnapshot) as exc:
        policy_issue = f"policy replay unavailable: {exc}"

    transitions: list[AcceptedTransition] = []
    prior_settlements: set[str] = set()
    current_state = TaskState.ACTIVE
    try:
        for index in range(n):
            try:
                transition = ledger.get_transition("0x" + normalized_instance, index)
            except Exception as exc:
                raise _UnavailableArtifact(
                    f"on-chain transition {index} unavailable: {type(exc).__name__}: {exc}"
                ) from exc
            if _state(transition.previous_state) != current_state:
                raise _IncorrectArtifact(f"state-chain mismatch at transition {index}")
            if _state(transition.next_state) != TaskState.ACTIVE:
                raise _IncorrectArtifact(f"paid transition {index} must remain active")

            action_hash = _digest(transition.action_hash, f"Action[{index}]")
            payment_hash = _digest(transition.payment_hash, f"Payment[{index}]")
            evidence_hash = _digest(transition.evidence_hash, f"Evidence[{index}]")
            action = _decode_action(_load(store, action_hash, f"Action[{index}]"))
            payment = _decode_payment(_load(store, payment_hash, f"Payment[{index}]"))
            evidence = _decode_evidence(_load(store, evidence_hash, f"Evidence[{index}]"))

            if _digest(payment.action_id, "Payment.action_id") != action_hash:
                raise _IncorrectArtifact(f"Payment.action_id mismatch at transition {index}")
            if _digest(evidence.action_id, "Evidence.action_id") != action_hash:
                raise _IncorrectArtifact(f"Evidence.action_id mismatch at transition {index}")
            if evidence.instance_id.lower().removeprefix("0x") != normalized_instance:
                raise _IncorrectArtifact(f"Evidence.instance_id mismatch at transition {index}")
            if payment.payee != action.provider or payment.amount != action.value:
                raise _IncorrectArtifact(f"Payment economic terms mismatch at transition {index}")
            if evidence.receipt_ref is not None and evidence.receipt_ref != payment.reference:
                raise _IncorrectArtifact(f"Evidence.receipt_ref mismatch at transition {index}")
            if not payment.reference.strip():
                raise _IncorrectArtifact(f"missing settlement reference at transition {index}")
            settlement_key = _settlement_key(payment.reference)
            if settlement_key in prior_settlements:
                raise _IncorrectArtifact(f"reused settlement reference at transition {index}")
            prior_settlements.add(settlement_key)
            report.settlement_refs.append(payment.reference)
            transitions.append(AcceptedTransition(action, payment, evidence, current_state, TaskState.ACTIVE))
            current_state = TaskState.ACTIVE

        # A final contract state may be Active or a terminal state. This is a
        # separate finalization; it is not an additional paid transition.
        if final_state not in {TaskState.ACTIVE, TaskState.COMPLETED, TaskState.FAILED, TaskState.REVOKED}:
            raise _IncorrectArtifact("invalid finalized task state")

    except _UnavailableArtifact as exc:
        report.issues.append(str(exc))
        return report
    except (AttributeError, _IncorrectArtifact) as exc:
        report.structural_consistency = "fail"
        report.issues.append(str(exc))
        return report

    report.structural_consistency = "pass"
    if policy_issue is not None:
        report.issues.append(policy_issue)
        return report
    assert evaluator is not None

    # Candidate history: transitions recorded on-chain, NOT assumed admitted.
    # Apply each action against the PRIOR recorded prefix, never final state.
    prior: list[AcceptedTransition] = []
    for index, transition in enumerate(transitions):
        try:
            decision, reason = evaluator.evaluate(
                intent, transition.previous_state, prior, transition.action
            )
        except (ValueError, KeyError, TypeError) as exc:
            report.admission_replay = "fail"
            report.denied_transition = index
            report.issues.append(f"admission replay failed at transition {index}: {exc}")
            return report
        if decision != Decision.PERMIT:
            report.admission_replay = "fail"
            report.denied_transition = index
            report.issues.append(f"admission denied at transition {index}: {reason}")
            return report
        prior.append(transition)

    report.admission_replay = "pass"
    return report
