"""Create NEW task instances with durable, commitment-addressed policy inputs.

The recorded policyHash is the SHA-256 commitment of the exact policy snapshot
stored in ArtifactStore. The existing LifecycleTracker contract is unchanged.
This is an initialization facility for new instances, not a migration of old
ones or an admission-replay verifier.
"""

from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .artifact_store import ArtifactStore
from .canonical import canonical_json_bytes, content_id
from .controller import TaskContext
from .model import Intent
from .policy import PolicyEvaluator
from .policy_snapshot import export_policy_snapshot, load_committed_policy


# The prototype's Solidity contract allows paid Active -> Active transitions,
# followed by one of these terminal finalizations. This is a MODEL artifact,
# not a replacement for the contract's enforcement.
DEFAULT_LIFECYCLE_MODEL: dict[str, Any] = {
    "schema": "verifiable-task-lifecycle-model/v1",
    "initial_state": "active",
    "paid_transition": {"from": "active", "to": "active"},
    "terminal_states": ["completed", "failed", "revoked"],
}


class TaskCreationError(RuntimeError):
    """Task creation could not be confirmed. Check chain before retrying."""


class InstanceRecorder(Protocol):
    """Synchronous ledger adapter; returns a CONFIRMED creation transaction hash."""

    def create_instance(
        self, *, instance_id: str, intent_hash: str, model_hash: str, policy_hash: str
    ) -> str: ...


@dataclass(frozen=True)
class PreparedTaskInstance:
    """Identifiers after all three referenced artifacts have been persisted."""

    instance_id: str  # lowercase 64-digit hex; contract ABI uses 0x-prefixed bytes32
    intent_id: str
    model_id: str
    policy_id: str

    @property
    def contract_arguments(self) -> dict[str, str]:
        return {
            "instance_id": "0x" + self.instance_id,
            "intent_hash": "0x" + self.intent_id,
            "model_hash": "0x" + self.model_id,
            "policy_hash": "0x" + self.policy_id,
        }


@dataclass(frozen=True)
class CreatedTaskInstance:
    prepared: PreparedTaskInstance
    transaction_hash: str
    context: TaskContext
    manifest_path: Path


def _instance_id(value: str | None, intent_id: str) -> str:
    if value is None:
        # Bind random instance uniqueness to the canonical Intent identifier.
        return content_id({"intent_id": intent_id, "nonce": secrets.token_hex(16)})
    if not isinstance(value, str):
        raise ValueError("instance_id must be a 32-byte hexadecimal string")
    result = value.lower().removeprefix("0x")
    if re.fullmatch(r"[0-9a-f]{64}", result) is None or result == "0" * 64:
        raise ValueError("instance_id must be a nonzero 32-byte hexadecimal string")
    return result


def _put_and_check(store: ArtifactStore, data: dict[str, Any]) -> str:
    """Do not submit a commitment unless its exact artifact is retrievable."""
    identifier = store.put(data)
    if not isinstance(identifier, str) or identifier != content_id(data):
        raise TaskCreationError("artifact store returned an incorrect content identifier")
    try:
        loaded = store.get(identifier)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise TaskCreationError(f"artifact {identifier} cannot be reloaded") from exc
    if content_id(loaded) != identifier:
        raise TaskCreationError(f"artifact {identifier} does not match its identifier")
    return identifier


def prepare_task_instance(
    *,
    intent: Intent,
    evaluator: PolicyEvaluator,
    store: ArtifactStore,
    instance_id: str | None = None,
    lifecycle_model: dict[str, Any] | None = None,
) -> PreparedTaskInstance:
    """Persist Intent, lifecycle model and policy snapshot for a NEW task.

    No chain transaction is sent here. A return value guarantees that each
    content-addressed object has been reloaded and checked locally.
    """
    if not isinstance(intent, Intent):
        raise TypeError("intent must be an Intent")
    if not isinstance(evaluator, PolicyEvaluator):
        raise TypeError("evaluator must be a PolicyEvaluator")
    model = DEFAULT_LIFECYCLE_MODEL if lifecycle_model is None else lifecycle_model
    if not isinstance(model, dict):
        raise TypeError("lifecycle_model must be an object")
    if model != DEFAULT_LIFECYCLE_MODEL:
        raise ValueError("unsupported lifecycle model for the current LifecycleTracker contract")

    intent_artifact = intent.as_artifact()
    task_id = _instance_id(instance_id, content_id(intent_artifact))
    snapshot = export_policy_snapshot(evaluator.catalog)

    # A failed write or verification stops creation before any ledger call.
    intent_id = _put_and_check(store, intent_artifact)
    model_id = _put_and_check(store, model)
    policy_id = _put_and_check(store, snapshot)

    # Confirm the persisted snapshot can actually reconstruct the policy
    # using the code fingerprint committed in the snapshot.
    load_committed_policy(store.get(policy_id), expected_commitment="0x" + policy_id)
    return PreparedTaskInstance(task_id, intent_id, model_id, policy_id)


def register_task_instance(
    *, prepared: PreparedTaskInstance,
    intent: Intent,
    store: ArtifactStore,
    recorder: InstanceRecorder,
) -> CreatedTaskInstance:
    """Register prepared commitments and write a local index AFTER confirmation.

    The index is a lookup convenience and is NOT itself a trusted artifact:
    the verifier must read expected commitments from the ledger. On failure,
    content-addressed objects may remain in the store; no success index is
    written unless the recorder confirms success.
    """
    if content_id(intent.as_artifact()) != prepared.intent_id:
        raise TaskCreationError("Intent differs from prepared task")
    for identifier in (prepared.intent_id, prepared.model_id, prepared.policy_id):
        if content_id(store.get(identifier)) != identifier:
            raise TaskCreationError("prepared artifact unavailable or modified: " + identifier)
    load_committed_policy(
        store.get(prepared.policy_id), expected_commitment="0x" + prepared.policy_id
    )

    # Avoid falsely treating an existing local task as newly registered.
    path = store.root / "instances" / f"{prepared.instance_id}.json"
    if path.exists():
        raise TaskCreationError("local task manifest already exists: " + prepared.instance_id)

    tx_hash = recorder.create_instance(**prepared.contract_arguments)
    if not isinstance(tx_hash, str) or re.fullmatch(r"0x[0-9a-fA-F]{64}", tx_hash) is None:
        raise TaskCreationError("recorder did not return a confirmed transaction hash")

    manifest = {
        "schema": "verifiable-task-instance-index/v1",
        "instance_id": prepared.instance_id,
        "intent_id": prepared.intent_id,
        "model_id": prepared.model_id,
        "policy_id": prepared.policy_id,
        "creation_tx": tx_hash,
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Exclusive create avoids overwriting an existing successful index.
        with path.open("x", encoding="utf-8") as file:
            file.write(canonical_json_bytes(manifest).decode("utf-8") + "\n")
    except OSError as exc:
        raise TaskCreationError(
            f"creation transaction {tx_hash} confirmed but local manifest could not be saved; "
            "reconcile before attempting another creation"
        ) from exc
    return CreatedTaskInstance(
        prepared=prepared,
        transaction_hash=tx_hash,
        context=TaskContext(prepared.instance_id, intent),
        manifest_path=path,
    )


def create_task_instance(
    *, intent: Intent,
    evaluator: PolicyEvaluator,
    store: ArtifactStore,
    recorder: InstanceRecorder,
    instance_id: str | None = None,
    lifecycle_model: dict[str, Any] | None = None,
) -> CreatedTaskInstance:
    """One entry point for policy-backed initialization and DLT registration."""
    prepared = prepare_task_instance(
        intent=intent, evaluator=evaluator, store=store,
        instance_id=instance_id, lifecycle_model=lifecycle_model,
    )
    return register_task_instance(
        prepared=prepared, intent=intent, store=store, recorder=recorder
    )
