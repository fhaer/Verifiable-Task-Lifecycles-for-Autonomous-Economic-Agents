"""Fail-closed reconciliation for an interrupted Step 4 task creation.

This module never creates an instance. A caller must independently corroborate
its original createInstance transaction before using this to resume transitions.
The experiment's Payment/Evidence objects remain SYNTHETIC and settlement
verification remains unverified.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .artifact_store import ArtifactStore
from .canonical import content_id
from .committed_verifier import verify_committed_task, RecordedTaskVerificationReport, TaskLedgerReader
from .model import TaskState
from .policy_snapshot import load_committed_policy

CREATION_SELECTOR = bytes.fromhex("d831bba8")
CREATION_EVENT_TOPIC = bytes.fromhex(
    "b83bd3e1238bd470bced3919e62d0551496003aac4fb9949adffad0e1a6801f5"
)
HEX32 = re.compile(r"0x[0-9a-fA-F]{64}\Z")


class RecoveryError(RuntimeError):
    pass


def _hex32(value: Any, label: str) -> str:
    if not isinstance(value, str) or HEX32.fullmatch(value) is None:
        raise RecoveryError(f"{label} must be a 0x-prefixed bytes32 value")
    return value.lower()


def _digest(value: str) -> bytes:
    return bytes.fromhex(value.removeprefix("0x"))


@dataclass(frozen=True)
class ReconciledTask:
    instance_id: str
    creation_tx: str
    creator: str
    transition_count: int
    report: RecordedTaskVerificationReport

    def as_dict(self) -> dict[str, Any]:
        return {
            "instance_id": self.instance_id,
            "creation_tx": self.creation_tx,
            "creator": self.creator,
            "transition_count": self.transition_count,
            "verification": self.report.as_dict(),
            "actual_payments": False,
            "settlement_check": "unverified",
        }


def _check_artifacts(journal: dict, store: ArtifactStore) -> None:
    for key in ("instance_id", "intent_hash", "model_hash", "policy_hash", "contract"):
        if key not in journal:
            raise RecoveryError(f"journal missing {key}")
    instance = _hex32(journal["instance_id"], "instance_id")
    if instance == "0x" + "00" * 32:
        raise RecoveryError("zero instance ID")
    for label in ("intent_hash", "model_hash", "policy_hash"):
        identifier = _hex32(journal[label], label).removeprefix("0x")
        try:
            obj = store.get(identifier)
        except (OSError, ValueError) as exc:
            raise RecoveryError(f"{label} artifact missing or unreadable") from exc
        if content_id(obj) != identifier:
            raise RecoveryError(f"{label} does not match stored artifact")
        if label == "policy_hash":
            load_committed_policy(obj, expected_commitment="0x" + identifier)

    transitions = journal.get("transitions")
    if not isinstance(transitions, list) or len(transitions) != 2:
        raise RecoveryError("journal must contain exactly two prepared transitions")
    settlement_refs = set()
    for index, entry in enumerate(transitions):
        if not isinstance(entry, dict):
            raise RecoveryError(f"transition {index} is not an object")
        items = {}
        for label, key in (("action", "action_hash"), ("payment", "payment_hash"), ("evidence", "evidence_hash")):
            identifier = _hex32(entry.get(key), f"transition {index} {key}").removeprefix("0x")
            try:
                obj = store.get(identifier)
            except (OSError, ValueError) as exc:
                raise RecoveryError(f"transition {index}: {label} artifact missing or unreadable") from exc
            if content_id(obj) != identifier or not isinstance(obj, dict):
                raise RecoveryError(f"transition {index}: {label} artifact does not match commitment")
            items[label] = (identifier, obj)
        action_id, action = items["action"]
        _, payment = items["payment"]
        _, evidence = items["evidence"]
        ref = entry.get("synthetic_settlement_reference")
        if (
            not isinstance(ref, str)
            or not ref.startswith("SIMULATED-NO-SETTLEMENT:")
            or ref in settlement_refs
            or payment.get("reference") != ref
            or evidence.get("receipt_ref") != ref
            or payment.get("action_id") != action_id
            or evidence.get("action_id") != action_id
            or evidence.get("instance_id", "").lower().removeprefix("0x") != instance.removeprefix("0x")
            or payment.get("payee") != action.get("provider")
            or payment.get("amount") != action.get("value")
            or not isinstance(payment.get("amount"), int)
            or isinstance(payment.get("amount"), bool)
        ):
            raise RecoveryError(f"transition {index}: synthetic Action-Payment-Evidence binding invalid")
        settlement_refs.add(ref)


def _validate_creation_receipt(journal: dict, creation_tx: str, w3) -> str:
    """Verify original broadcast, calldata, event and sender; never submit a tx."""
    txid = _hex32(creation_tx, "creation transaction")
    tx = w3.eth.get_transaction(txid)
    receipt = w3.eth.get_transaction_receipt(txid)
    if int(receipt["status"]) != 1:
        raise RecoveryError("original creation transaction did not succeed")
    address = journal["contract"].lower()
    if str(tx["to"]).lower() != address or str(receipt["to"]).lower() != address:
        raise RecoveryError("original creation transaction targets a different contract")
    expected_call = CREATION_SELECTOR + b"".join(
        _digest(_hex32(journal[key], key))
        for key in ("instance_id", "intent_hash", "model_hash", "policy_hash")
    )
    if bytes(tx["input"]) != expected_call:
        raise RecoveryError("original creation calldata differs from persisted commitments")
    creator = str(tx["from"]).lower()
    expected_topic_id = _digest(journal["instance_id"])
    expected_topic_creator = bytes.fromhex(creator.removeprefix("0x")).rjust(32, b"\x00")
    if len(expected_topic_creator) != 32:
        raise RecoveryError("creation sender address malformed")
    matches = 0
    for log in receipt["logs"]:
        if str(log["address"]).lower() != address:
            continue
        topics = [bytes(topic) for topic in log["topics"]]
        if (len(topics) == 3 and topics[0] == CREATION_EVENT_TOPIC
            and topics[1] == expected_topic_id and topics[2] == expected_topic_creator
            and bytes(log["data"]) == (1).to_bytes(32, "big")):
            matches += 1
    if matches != 1:
        raise RecoveryError("expected deployed InstanceCreated event absent or ambiguous")
    return creator


def reconcile_recorded_prefix(
    *, journal: dict, creation_tx: str, store: ArtifactStore,
    ledger: TaskLedgerReader, w3,
) -> ReconciledTask:
    """Read-only reconciliation; only an exact prefix of 0, 1, or 2 is safe."""
    if journal.get("schema") != "admission-replay-experiment-journal/v1":
        raise RecoveryError("unsupported experiment journal schema")
    if journal.get("actual_payments") is not False:
        raise RecoveryError("recovery is restricted to the synthetic-payment experiment")
    _check_artifacts(journal, store)
    creator = _validate_creation_receipt(journal, creation_tx, w3)
    task_id = journal["instance_id"]
    instance = ledger.get_instance(task_id)
    if (
        instance.intent_hash.lower() != journal["intent_hash"].lower()
        or instance.model_hash.lower() != journal["model_hash"].lower()
        or instance.policy_hash.lower() != journal["policy_hash"].lower()
        or instance.creator.lower() != creator
        or instance.state != TaskState.ACTIVE
    ):
        raise RecoveryError("on-chain instance is not the expected active task")
    n = instance.transition_count
    if type(n) is not int or n not in (0, 1, 2):
        raise RecoveryError("unexpected transition count; do not write")
    for index in range(n):
        record = ledger.get_transition(task_id, index)
        expected = journal["transitions"][index]
        if (
            record.previous_state != TaskState.ACTIVE
            or record.next_state != TaskState.ACTIVE
            or record.action_hash.lower() != expected["action_hash"].lower()
            or record.payment_hash.lower() != expected["payment_hash"].lower()
            or record.evidence_hash.lower() != expected["evidence_hash"].lower()
        ):
            raise RecoveryError(f"on-chain transition {index} differs from prepared history")
    report = verify_committed_task(instance_id=task_id, store=store, ledger=ledger)
    if report.structural_consistency != "pass":
        raise RecoveryError("existing committed prefix did not pass structural verification")
    if n < 2 and report.admission_replay != "pass":
        raise RecoveryError("existing committed prefix did not pass admission replay")
    if n == 2 and (
        report.admission_replay != "fail"
        or report.denied_transition != 1
        or not any("equivalent service already succeeded" in issue for issue in report.issues)
    ):
        raise RecoveryError("completed adversarial history does not demonstrate the prior-success counterexample")
    if report.settlement_check != "unverified":
        raise RecoveryError("experiment must never claim successful payment settlement")
    return ReconciledTask(task_id, creation_tx, creator, n, report)
