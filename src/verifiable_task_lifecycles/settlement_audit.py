"""Optional read-only token-transfer audit of ledger-committed Payment artifacts.

Requires previously successful structural verification. Payee and logical
budget price are obtained from the *committed* policy snapshot; chain, asset,
and atomic unit conversion are externally trusted verifier parameters.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from .artifact_store import ArtifactStore
from .committed_verifier import RecordedTaskVerificationReport, TaskLedgerReader
from .payment_assurance import AuthorizedPaymentTerms, SettlementEvidenceResult, verify_erc20_transfer
from .policy_snapshot import load_committed_policy


@dataclass(frozen=True)
class TaskSettlementAudit:
    status: Literal["pass", "fail", "unverified"]
    checks: tuple[SettlementEvidenceResult, ...]
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason": self.reason,
            "checks": [check.as_dict() for check in self.checks],
        }


def audit_committed_settlements(
    *,
    instance_id: str,
    ledger: TaskLedgerReader,
    store: ArtifactStore,
    recorded_report: RecordedTaskVerificationReport,
    web3: Any,
    asset: str,
    atomic_units_per_budget_unit: int,
    network: str,
    min_confirmations: int = 1,
) -> TaskSettlementAudit:
    """Never interpret synthetic references, missing evidence, or RPC errors as pass."""
    if recorded_report.instance_id.lower().removeprefix("0x") != instance_id.lower().removeprefix("0x"):
        return TaskSettlementAudit("unverified", (), "verification report belongs to another instance")
    if recorded_report.structural_consistency != "pass":
        return TaskSettlementAudit("unverified", (), "structural verification not passed")
    if recorded_report.admission_replay == "unverified":
        return TaskSettlementAudit("unverified", (), "committed policy semantics unavailable")
    try:
        instance = ledger.get_instance(instance_id)
        snapshot = store.get(instance.policy_hash.removeprefix("0x"))
        evaluator = load_committed_policy(snapshot, expected_commitment=instance.policy_hash)
        # Avoid a vacuous positive settlement result for an empty history.
        if not instance.transition_count:
            return TaskSettlementAudit("unverified", (), "no recorded paid transitions")
    except Exception as exc:
        return TaskSettlementAudit("unverified", (), f"committed policy unavailable: {exc}")
    checks: list[SettlementEvidenceResult] = []
    for index in range(instance.transition_count):
        try:
            transition = ledger.get_transition(instance_id, index)
            action = store.get(transition.action_hash.removeprefix("0x"))
            payment = store.get(transition.payment_hash.removeprefix("0x"))
            entry = evaluator.catalog.entry(action["service"])
            terms = AuthorizedPaymentTerms.from_catalog(
                entry, network=network, asset=asset,
                atomic_units_per_budget_unit=atomic_units_per_budget_unit,
            )
            reference = payment["reference"]
            if payment.get("protocol") != "x402-v2":
                checks.append(SettlementEvidenceResult(
                    "unverified", f"transition {index}: unsupported payment protocol", str(reference)
                ))
                continue
            if payment.get("network") != terms.network:
                checks.append(SettlementEvidenceResult(
                    "fail", f"transition {index}: recorded payment network mismatch", str(reference)
                ))
                continue
            check = verify_erc20_transfer(
                web3, reference=reference, payer=payment["payer"], expected=terms,
                min_confirmations=min_confirmations,
            )
            checks.append(check)
        except Exception as exc:
            checks.append(SettlementEvidenceResult(
                "unverified", f"transition {index}: cannot independently check transfer: {exc}",
                recorded_report.settlement_refs[index] if index < len(recorded_report.settlement_refs) else "",
            ))
    status: Literal["pass", "fail", "unverified"]
    if any(c.status == "fail" for c in checks):
        status = "fail"
    elif any(c.status == "unverified" for c in checks):
        status = "unverified"
    else:
        status = "pass"
    return TaskSettlementAudit(status, tuple(checks))
