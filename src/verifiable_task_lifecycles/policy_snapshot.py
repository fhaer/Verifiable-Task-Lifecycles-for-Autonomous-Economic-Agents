"""Commitment-checked snapshot of the existing deterministic task policy.

This module deliberately does not modify the admission rules. A freshly
created task should commit the SHA-256 content identifier of the exported
snapshot in its existing on-chain policy-hash slot. The independent verifier
must validate this snapshot against that slot BEFORE replaying admission.

Caution: a controller-created commitment identifies its chosen policy, but
is not evidence that the principal approved it.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from . import canonical, model, policy
from .canonical import content_commitment
from .policy import CatalogEntry, PolicyEvaluator, TrustedCatalog

SCHEMA = "verifiable-task-policy-snapshot/v1"
IMPLEMENTATION = "verifiable_task_lifecycles.policy.PolicyEvaluator"
CATALOG_KEYS = {
    "service", "provider", "value", "endpoint", "pay_to", "equivalence_group"
}


class PolicySnapshotError(ValueError):
    """Base class for policy provenance and replay-input errors."""


class PolicyCommitmentMismatch(PolicySnapshotError):
    """Policy bytes do not match the policy commitment in the ledger."""


class UnsupportedPolicySnapshot(PolicySnapshotError):
    """Unknown or unavailable policy semantics; replay must be unverified."""


class InvalidPolicySnapshot(PolicySnapshotError):
    """Malformed snapshot; do not proceed with replay."""


def _sha256_source(module: Any) -> str:
    """Pin source bytes, not a human-editable version string.

    Modules that cannot be checked from available source must not silently
    fall back to a different implementation.
    """
    filename = getattr(module, "__file__", None)
    if filename is None or Path(filename).suffix != ".py":
        raise UnsupportedPolicySnapshot(f"Python source unavailable: {module.__name__}")
    try:
        return hashlib.sha256(Path(filename).read_bytes()).hexdigest()
    except OSError as exc:
        raise UnsupportedPolicySnapshot(f"Python source unavailable: {module.__name__}") from exc


def _code_fingerprints() -> dict[str, str]:
    # Replay depends on rule semantics, the TaskState/data model, AND the
    # canonical serializer used to verify the on-chain policy commitment.
    return {
        "policy_snapshot.py": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "canonical.py": _sha256_source(canonical),
        "model.py": _sha256_source(model),
        "policy.py": _sha256_source(policy),
    }


def export_policy_snapshot(catalog: TrustedCatalog) -> dict[str, Any]:
    """Export one canonical, self-describing policy for NEW task instances.

    This uses exactly the terms currently consulted by PolicyEvaluator;
    no broader natural-language Intent semantics are claimed.  The Intent
    itself is committed separately by the existing lifecycle contract.
    """
    entries = list(catalog._by_service.values())
    if not entries:
        raise InvalidPolicySnapshot("empty catalog")
    if len({entry.service for entry in entries}) != len(entries):
        raise InvalidPolicySnapshot("duplicate service")
    return {
        "schema": SCHEMA,
        "evaluator": {
            "implementation": IMPLEMENTATION,
            "source_sha256": _code_fingerprints(),
        },
        "catalog": [
            {
                "service": entry.service,
                "provider": entry.provider,
                "value": entry.value,
                "endpoint": entry.endpoint,
                "pay_to": entry.pay_to,
                "equivalence_group": entry.equivalence_group,
            }
            for entry in sorted(entries, key=lambda entry: entry.service)
        ],
    }


def policy_commitment(snapshot: dict[str, Any]) -> str:
    """Return the 0x-prefixed bytes32 value for the contract policy hash."""
    return content_commitment(snapshot)


def _normalized_hash(value: str) -> str:
    if not isinstance(value, str):
        raise InvalidPolicySnapshot("expected policy commitment must be hexadecimal")
    value = value.lower().removeprefix("0x")
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise InvalidPolicySnapshot("expected policy commitment must be a 32-byte hash")
    return value


def load_committed_policy(
    snapshot: dict[str, Any] | None,
    *,
    expected_commitment: str,
) -> PolicyEvaluator:
    """Validate task policy provenance and construct a replay evaluator.

    The expected commitment MUST come from a verified on-chain task instance,
    not from the untrusted artifact bundle. A missing policy must be marked
    'unverified'; a hash mismatch is a commitment/integrity failure. An unknown
    implementation must not be substituted with the current runtime policy.
    """
    if snapshot is None:
        raise UnsupportedPolicySnapshot("committed policy artifact unavailable")
    if not isinstance(snapshot, dict):
        raise InvalidPolicySnapshot("policy artifact is not a JSON object")

    if _normalized_hash(policy_commitment(snapshot)) != _normalized_hash(expected_commitment):
        raise PolicyCommitmentMismatch("policy artifact does not match on-chain commitment")

    if set(snapshot) != {"schema", "evaluator", "catalog"} or snapshot["schema"] != SCHEMA:
        raise UnsupportedPolicySnapshot("unsupported policy artifact schema")
    evaluator = snapshot["evaluator"]
    if not isinstance(evaluator, dict) or set(evaluator) != {"implementation", "source_sha256"}:
        raise InvalidPolicySnapshot("malformed evaluator metadata")
    if evaluator["implementation"] != IMPLEMENTATION:
        raise UnsupportedPolicySnapshot("unknown evaluator implementation")
    if evaluator["source_sha256"] != _code_fingerprints():
        raise UnsupportedPolicySnapshot("local evaluator semantics do not match committed source")

    catalog_data = snapshot["catalog"]
    if not isinstance(catalog_data, list) or not catalog_data:
        raise InvalidPolicySnapshot("missing catalog entries")
    entries: list[CatalogEntry] = []
    services: set[str] = set()
    for entry in catalog_data:
        if not isinstance(entry, dict) or set(entry) != CATALOG_KEYS:
            raise InvalidPolicySnapshot("malformed catalog entry")
        if any(not isinstance(entry[k], str) or not entry[k] for k in (
            "service", "provider", "endpoint", "pay_to"
        )):
            raise InvalidPolicySnapshot("invalid catalog string")
        if type(entry["value"]) is not int or entry["value"] < 0:
            raise InvalidPolicySnapshot("catalog price must be a nonnegative integer")
        if entry["equivalence_group"] is not None and (
            not isinstance(entry["equivalence_group"], str) or not entry["equivalence_group"]
        ):
            raise InvalidPolicySnapshot("invalid equivalence group")
        if entry["service"] in services:
            raise InvalidPolicySnapshot("duplicate service in committed catalog")
        services.add(entry["service"])
        entries.append(CatalogEntry(**entry))

    return PolicyEvaluator(TrustedCatalog(entries))
