"""Step 5: deterministic x402 exact-term admission and independent ERC-20 evidence.

This module does not sign, send, or retry payments. It intentionally leaves the
committed policy snapshot v1 untouched (source hashes are part of that format).
Trusted network, asset, and atomic-units-per-budget-unit settings are external
verification assumptions; provider/recipient/price in budget units are read
from the committed catalog. No service-result attestation or history
completeness is implied.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal, Mapping

from .policy import CatalogEntry

_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}\Z")
_TX_HASH = re.compile(r"0x[0-9a-fA-F]{64}\Z")
_NETWORK = re.compile(r"eip155:[1-9][0-9]*\Z")
_TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


class PaymentTermsMismatch(ValueError):
    """An x402 requirement is not exactly the controller-authorized payment."""


def _address(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _ADDRESS.fullmatch(value):
        raise ValueError(f"{name} must be a 20-byte EVM address")
    return value.lower()


def _positive_int(value: Any, name: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


@dataclass(frozen=True)
class AuthorizedPaymentTerms:
    """Exact EVM payment terms resolved by a controller, never by the planner.

    ``atomic_amount`` is the token's base-unit amount, not a USD price. The
    trusted caller must provide the network, token, and unit conversion.
    """

    network: str
    asset: str
    pay_to: str
    atomic_amount: int

    def __post_init__(self) -> None:
        if not isinstance(self.network, str) or not _NETWORK.fullmatch(self.network):
            raise ValueError("network must be an EVM CAIP-2 identifier")
        _address(self.asset, "asset")
        _address(self.pay_to, "pay_to")
        _positive_int(self.atomic_amount, "atomic_amount")

    @classmethod
    def from_catalog(
        cls,
        entry: CatalogEntry,
        *,
        network: str,
        asset: str,
        atomic_units_per_budget_unit: int,
    ) -> "AuthorizedPaymentTerms":
        _positive_int(atomic_units_per_budget_unit, "atomic_units_per_budget_unit")
        _positive_int(entry.value, "catalog value")
        return cls(
            network=network,
            asset=asset,
            pay_to=entry.pay_to,
            atomic_amount=entry.value * atomic_units_per_budget_unit,
        )


def _requirement_value(requirement: Any, name: str) -> Any:
    """Support the x402 2.x Pydantic model and plain dictionary fixtures."""
    if isinstance(requirement, Mapping):
        return requirement.get(name, requirement.get("pay_to" if name == "payTo" else name))
    if hasattr(requirement, "model_dump"):
        return _requirement_value(requirement.model_dump(by_alias=True), name)
    return getattr(requirement, "pay_to" if name == "payTo" else name, None)


def validate_selected_requirements(requirement: Any, expected: AuthorizedPaymentTerms) -> None:
    """Reject a selected challenge *before* the SDK creates payment payloads."""
    scheme = _requirement_value(requirement, "scheme")
    network = _requirement_value(requirement, "network")
    asset = _requirement_value(requirement, "asset")
    recipient = _requirement_value(requirement, "payTo")
    amount = _requirement_value(requirement, "amount")
    if scheme != "exact" or network != expected.network:
        raise PaymentTermsMismatch("unauthorized scheme or network")
    try:
        if _address(asset, "asset") != expected.asset.lower():
            raise PaymentTermsMismatch("unauthorized token asset")
        if _address(recipient, "payTo") != expected.pay_to.lower():
            raise PaymentTermsMismatch("unauthorized payment recipient")
    except ValueError as exc:
        if isinstance(exc, PaymentTermsMismatch):
            raise
        raise PaymentTermsMismatch("malformed token asset or payment recipient") from exc
    if type(amount) is int:
        atomic_amount = amount
    elif isinstance(amount, str) and re.fullmatch(r"[0-9]+", amount):
        atomic_amount = int(amount)
    else:
        raise PaymentTermsMismatch("invalid atomic payment amount")
    if atomic_amount != expected.atomic_amount:
        raise PaymentTermsMismatch("payment amount differs from trusted catalog")


@dataclass(frozen=True)
class SettlementEvidenceResult:
    status: Literal["pass", "fail", "unverified"]
    reason: str
    reference: str
    observed_amount: int | None = None
    block_number: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason": self.reason,
            "reference": self.reference,
            "observed_amount": self.observed_amount,
            "block_number": self.block_number,
        }


def _hex(value: Any) -> str:
    if isinstance(value, (bytes, bytearray)):
        return "0x" + bytes(value).hex()
    if isinstance(value, str):
        return value.lower() if value.lower().startswith("0x") else "0x" + value.lower()
    if hasattr(value, "hex"):
        h = value.hex()
        return h.lower() if h.lower().startswith("0x") else "0x" + h.lower()
    raise ValueError("not hexadecimal bytes")


def _field(obj: Any, name: str, alternative: str | None = None) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(name, obj.get(alternative)) if alternative else obj.get(name)
    value = getattr(obj, name, None)
    return value if value is not None else getattr(obj, alternative, None) if alternative else value


def verify_erc20_transfer(
    web3: Any,
    *,
    reference: str,
    payer: str,
    expected: AuthorizedPaymentTerms,
    min_confirmations: int = 1,
) -> SettlementEvidenceResult:
    """Read-only verification of one exact ERC-20 Transfer in a successful tx.

    Returns unverified on RPC unavailability and fail on observed mismatches.
    The trusted RPC/chain, token contract, and transfer event semantics remain
    explicit assumptions. A Transfer log is not a provider-signed receipt.
    """
    if not isinstance(reference, str) or not _TX_HASH.fullmatch(reference):
        return SettlementEvidenceResult("unverified", "no EVM settlement transaction hash", str(reference))
    try:
        payer_addr = _address(payer, "payer")
        if type(min_confirmations) is not int or min_confirmations < 1:
            raise ValueError("min_confirmations must be positive")
    except ValueError as exc:
        return SettlementEvidenceResult("unverified", f"invalid trusted verification input: {exc}", reference)
    try:
        chain_id = int(web3.eth.chain_id)
        if expected.network != f"eip155:{chain_id}":
            return SettlementEvidenceResult("fail", "settlement network differs from trusted network", reference)
        receipt = web3.eth.get_transaction_receipt(reference)
    except Exception as exc:
        return SettlementEvidenceResult("unverified", f"RPC read unavailable: {type(exc).__name__}: {exc}", reference)
    if receipt is None:
        return SettlementEvidenceResult("unverified", "settlement receipt not available", reference)
    returned_hash = _field(receipt, "transactionHash", "transaction_hash")
    if returned_hash is not None:
        try:
            if _hex(returned_hash) != reference.lower():
                return SettlementEvidenceResult("fail", "receipt belongs to a different transaction", reference)
        except ValueError:
            return SettlementEvidenceResult("unverified", "malformed receipt transaction identifier", reference)
    if int(_field(receipt, "status") or 0) != 1:
        return SettlementEvidenceResult("fail", "settlement transaction did not succeed", reference)
    block_number = _field(receipt, "blockNumber", "block_number")
    if type(block_number) is not int or block_number <= 0:
        return SettlementEvidenceResult("unverified", "settlement block not established", reference)
    try:
        confirmations = int(web3.eth.block_number) - block_number + 1
    except Exception as exc:
        return SettlementEvidenceResult("unverified", f"confirmation depth unavailable: {exc}", reference)
    if confirmations < min_confirmations:
        return SettlementEvidenceResult("unverified", "insufficient settlement confirmations", reference, block_number=block_number)
    logs = _field(receipt, "logs")
    if not isinstance(logs, (list, tuple)):
        return SettlementEvidenceResult("unverified", "receipt logs unavailable", reference, block_number=block_number)
    matches: list[int] = []
    try:
        for log in logs:
            if _address(_field(log, "address"), "log.address") != expected.asset.lower():
                continue
            topics = _field(log, "topics")
            if not isinstance(topics, (list, tuple)) or len(topics) != 3:
                continue
            if _hex(topics[0]) != _TRANSFER_TOPIC:
                continue
            if not re.fullmatch(r"0x[0-9a-f]{64}", _hex(topics[1])) or \
                    not re.fullmatch(r"0x[0-9a-f]{64}", _hex(topics[2])):
                return SettlementEvidenceResult("fail", "malformed indexed address", reference)
            if _hex(topics[1])[-40:] != payer_addr.removeprefix("0x"):
                continue
            if _hex(topics[2])[-40:] != expected.pay_to.lower().removeprefix("0x"):
                continue
            data = _hex(_field(log, "data"))
            if not re.fullmatch(r"0x[0-9a-f]{64}", data):
                return SettlementEvidenceResult("fail", "malformed matching ERC-20 Transfer amount", reference)
            matches.append(int(data, 16))
    except (ValueError, TypeError) as exc:
        return SettlementEvidenceResult("unverified", f"malformed transfer log: {exc}", reference)
    if not matches:
        return SettlementEvidenceResult("fail", "no expected token transfer to recipient from payer", reference, block_number=block_number)
    if len(matches) != 1:
        return SettlementEvidenceResult("fail", "multiple matching token transfers in transaction", reference, block_number=block_number)
    if matches[0] != expected.atomic_amount:
        return SettlementEvidenceResult(
            "fail", "token transfer amount differs from authorized amount", reference,
            observed_amount=matches[0], block_number=block_number,
        )
    return SettlementEvidenceResult(
        "pass", "one matching ERC-20 Transfer emitted by trusted asset contract", reference,
        observed_amount=matches[0], block_number=block_number,
    )
