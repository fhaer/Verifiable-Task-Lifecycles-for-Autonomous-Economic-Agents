from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from typing import Any

from .payment_assurance import (
    AuthorizedPaymentTerms,
    PaymentTermsMismatch,
    validate_selected_requirements,
)


@dataclass(frozen=True)
class PaidResponse:
    body: Any
    transaction: str
    network: str
    payer: str | None
    settlement: dict[str, Any]


class PaymentOutcomeUncertain(RuntimeError):
    """A payment may have been authorized/settled; do not blindly retry it."""


class ServiceResponseFailedAfterSettlement(RuntimeError):
    """Provider reported settlement but failed to deliver a successful response."""

    def __init__(self, transaction: str, status_code: int):
        self.transaction = transaction
        self.status_code = status_code
        super().__init__(
            f"service returned HTTP {status_code} after reporting settlement {transaction}; "
            "reconcile transaction and preserve budget before any retry"
        )


def _decode_header(value: str) -> dict[str, Any]:
    value += "=" * (-len(value) % 4)
    decoded = json.loads(base64.b64decode(value, validate=True).decode("utf-8"))
    if not isinstance(decoded, dict):
        raise ValueError("settlement header must be a JSON object")
    return decoded


class X402PaymentClient:
    """x402 v2 `exact` client with per-request pre-signing economic authorization.

    The x402 SDK handles protocol negotiation and its paid HTTP retry. The
    before-payment hook validates the *selected* requirement, so changing the
    challenge between requests cannot bypass the check. An individual client
    is created for each request to avoid concurrent authorization-policy leaks.

    This adapter never retries failed/ambiguous paid requests on its own. The
    caller must persist/reconcile settlement status and account for spending.
    """

    def __init__(self, private_key: str):
        from eth_account import Account
        from x402.mechanisms.evm import EthAccountSigner

        account = Account.from_key(private_key)
        self._signer = EthAccountSigner(account)
        self._payer = account.address

    def _new_client(self) -> Any:
        from x402 import x402Client
        from x402.mechanisms.evm.exact.register import register_exact_evm_client

        client = x402Client()
        register_exact_evm_client(client, self._signer)
        return client

    async def request(
        self,
        method: str,
        url: str,
        *,
        terms: AuthorizedPaymentTerms,
        json_body: Any | None = None,
    ) -> PaidResponse:
        from x402 import AbortResult
        from x402.http.clients import x402HttpxClient

        if not isinstance(terms, AuthorizedPaymentTerms):
            raise ValueError("trusted AuthorizedPaymentTerms required before any x402 request")
        client = self._new_client()
        approved = False
        rejection: str | None = None

        def before_payment(context: Any) -> Any:
            nonlocal approved, rejection
            try:
                requirement = getattr(context, "selected_requirements", None)
                if requirement is None:
                    raise PaymentTermsMismatch("selected payment requirements unavailable")
                validate_selected_requirements(requirement, terms)
            except PaymentTermsMismatch as exc:
                rejection = str(exc)
                return AbortResult(reason=f"unauthorized x402 payment terms: {exc}")
            approved = True
            return None

        # This SDK hook runs before payment authorization is constructed.
        client.on_before_payment_creation(before_payment)
        try:
            async with x402HttpxClient(client) as http:
                response = await http.request(method=method, url=url, json=json_body)
                await response.aread()
        except Exception as exc:
            if rejection is not None:
                raise PaymentTermsMismatch(rejection) from exc
            if approved:
                raise PaymentOutcomeUncertain(
                    "paid request failed after payment authorization began; "
                    "settlement must be reconciled before another payment"
                ) from exc
            raise
        if rejection is not None:
            raise PaymentTermsMismatch(rejection)
        if not approved:
            raise PaymentOutcomeUncertain(
                "no validated payment requirement was observed; do not treat this as a paid result"
            )

        header = response.headers.get("PAYMENT-RESPONSE")
        if not header:
            raise PaymentOutcomeUncertain(
                "paid request returned without settlement evidence; reconcile before retry"
            )
        try:
            settlement = _decode_header(header)
        except (ValueError, TypeError, KeyError) as exc:
            raise PaymentOutcomeUncertain("malformed payment settlement response") from exc
        if settlement.get("success") is not True:
            raise PaymentOutcomeUncertain(
                "settlement response did not confirm successful execution"
            )
        tx = settlement.get("transaction")
        network = settlement.get("network")
        if not isinstance(tx, str) or re.fullmatch(r"0x[0-9a-fA-F]{64}", tx) is None:
            raise PaymentOutcomeUncertain("settlement response lacks a valid EVM transaction reference")
        if network != terms.network:
            raise PaymentOutcomeUncertain("settlement response network differs from authorized network")
        reported_payer = settlement.get("payer")
        if reported_payer is not None and (
            not isinstance(reported_payer, str) or
            reported_payer.lower() != self._payer.lower()
        ):
            raise PaymentOutcomeUncertain("settlement payer differs from authorized signer")
        if not 200 <= response.status_code < 300:
            raise ServiceResponseFailedAfterSettlement(tx, response.status_code)
        try:
            body = response.json()
        except Exception:
            body = response.text
        return PaidResponse(
            body=body,
            transaction=tx,
            network=network,
            payer=reported_payer or self._payer,
            settlement=settlement,
        )
