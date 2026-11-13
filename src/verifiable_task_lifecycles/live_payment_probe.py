"""Read-only x402 v2 challenge reconnaissance against independently pinned terms.

This module intentionally does not sign or send payments. Its output is not an
independent certificate of service identity: the caller must trust the catalog.
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from .payment_assurance import (
    AuthorizedPaymentTerms, PaymentTermsMismatch, validate_selected_requirements,
)
from .policy import CatalogEntry


class LivePreflightError(ValueError):
    """A quote could not be validated safely; do not initiate payment."""


@dataclass(frozen=True)
class LiveX402Config:
    endpoint: str
    method: str
    json_body: dict[str, Any]
    service: str
    provider: str
    catalog_value: int
    pay_to: str
    network: str
    asset: str
    atomic_units_per_budget_unit: int
    catalog_source: str

    @classmethod
    def load(cls, path: str | Path) -> "LiveX402Config":
        raw = json.loads(Path(path).read_text(encoding='utf-8'))
        required = {
            'endpoint', 'method', 'json_body', 'service', 'provider',
            'catalog_value', 'pay_to', 'network', 'asset',
            'atomic_units_per_budget_unit', 'catalog_source',
        }
        if not isinstance(raw, dict) or set(raw) != required:
            raise LivePreflightError('trusted configuration fields missing or unexpected')
        if type(raw['catalog_value']) is not int or raw['catalog_value'] < 1:
            raise LivePreflightError('catalog_value must be a positive integer')
        if not isinstance(raw['json_body'], dict) or len(json.dumps(raw['json_body'])) > 4096:
            raise LivePreflightError('json_body must be a small JSON object')
        if raw['method'] != 'POST':
            raise LivePreflightError('live experiment intentionally supports POST only')
        parts = urlsplit(raw['endpoint'])
        if (parts.scheme != 'https' or not parts.hostname or parts.username or parts.password
                or parts.fragment or parts.port not in (None, 443)):
            raise LivePreflightError('endpoint must be an unambiguous HTTPS URL')
        if not isinstance(raw['catalog_source'], str) or not raw['catalog_source'].startswith('https://'):
            raise LivePreflightError('an external catalog provenance URL is required')
        if not all(isinstance(raw[k], str) and raw[k] for k in ('service','provider','pay_to','network','asset')):
            raise LivePreflightError('invalid trusted catalog fields')
        try:
            config = cls(**raw)
            config.terms()
        except (TypeError, ValueError) as exc:
            raise LivePreflightError(f'invalid trusted payment terms: {exc}') from exc
        if config.network != 'eip155:84532':
            raise LivePreflightError('this experiment is restricted to Base Sepolia')
        if config.terms().atomic_amount > 10_000:
            raise LivePreflightError('experiment cap is 10,000 token atomic units (0.01 USDC)')
        return config

    def terms(self) -> AuthorizedPaymentTerms:
        entry = CatalogEntry(
            service=self.service, provider=self.provider, value=self.catalog_value,
            endpoint=self.endpoint, pay_to=self.pay_to,
        )
        return AuthorizedPaymentTerms.from_catalog(
            entry, network=self.network, asset=self.asset,
            atomic_units_per_budget_unit=self.atomic_units_per_budget_unit,
        )

    def safe_description(self) -> dict[str, Any]:
        return {
            'endpoint': self.endpoint, 'method': self.method, 'service': self.service,
            'provider': self.provider, 'catalog_source': self.catalog_source,
            'network': self.network, 'asset': self.asset, 'pay_to': self.pay_to,
            'catalog_value': self.catalog_value,
            'atomic_units_per_budget_unit': self.atomic_units_per_budget_unit,
            'expected_atomic_amount': self.terms().atomic_amount,
        }


def _read_challenge_json(headers: Mapping[str, str], body: bytes) -> dict[str, Any]:
    # x402 v2 requires PAYMENT-REQUIRED. Some servers also echo equivalent JSON
    # in the 402 response body, but an unauthenticated body is not authority.
    encoded = next((v for k, v in headers.items() if k.lower() == 'payment-required'), None)
    if encoded:
        if len(encoded) > 24_000:
            raise LivePreflightError('payment-required header too large')
        try:
            data = base64.b64decode(encoded + '=' * (-len(encoded) % 4), validate=True)
            challenge = json.loads(data)
        except (ValueError, UnicodeDecodeError) as exc:
            raise LivePreflightError('malformed x402 PAYMENT-REQUIRED header') from exc
    else:
        # Body-only challenge is accepted for reconnaissance only; the SDK is
        # ultimately responsible for x402 v2 negotiation and selected-term hook.
        if len(body) > 24_000:
            raise LivePreflightError('402 response body too large')
        try:
            challenge = json.loads(body)
        except (ValueError, UnicodeDecodeError) as exc:
            raise LivePreflightError('no decodable x402 v2 challenge') from exc
    if not isinstance(challenge, dict) or challenge.get('x402Version') != 2:
        raise LivePreflightError('not a supported x402 v2 challenge')
    accepts = challenge.get('accepts')
    if not isinstance(accepts, list) or not accepts or len(accepts) > 32:
        raise LivePreflightError('missing or excessive x402 payment alternatives')
    if not all(isinstance(v, dict) for v in accepts):
        raise LivePreflightError('malformed x402 payment alternatives')
    return challenge


def examine_challenge(status_code: int, headers: Mapping[str, str], body: bytes,
                      terms: AuthorizedPaymentTerms) -> dict[str, Any]:
    """Require HTTP 402 and at least one exactly matching offer; never auto-trust quote."""
    if status_code != 402:
        raise LivePreflightError(f'expected HTTP 402; received {status_code}; no payment authorized')
    challenge = _read_challenge_json(headers, body)
    failures = []
    matches = 0
    matched_offer = None
    for offer in challenge['accepts']:
        try:
            validate_selected_requirements(offer, terms)
            matches += 1
            if matched_offer is None:
                matched_offer = offer
        except PaymentTermsMismatch as exc:
            failures.append(str(exc))
    if not matches:
        raise LivePreflightError('no payment offer matches pinned catalog: ' + '; '.join(failures))
    # The actual observed matching offer must fail if the authorized price is
    # deliberately changed by one atomic unit. This invokes no SDK or signer.
    try:
        validate_selected_requirements(matched_offer, replace(terms, atomic_amount=terms.atomic_amount + 1))
    except PaymentTermsMismatch:
        live_negative = 'rejected-without-signing'
    else:
        raise LivePreflightError('observed quote incorrectly accepted under altered authorized price')
    # Deliberately omit untrusted arbitrary challenge metadata / external URLs.
    return {
        'x402_version': 2,
        'total_offers': len(challenge['accepts']),
        'matching_offers': matches,
        'rejected_offer_count': len(failures),
        'exact_match': True,
        'observed_quote_price_mismatch_control': live_negative,
        'server_quote_is_not_trusted_catalog': True,
    }


def check_negative_control(terms: AuthorizedPaymentTerms) -> dict[str, Any]:
    """No-signature negative control: a price increase must be rejected."""
    deliberately_incorrect = {
        'scheme': 'exact', 'network': terms.network, 'asset': terms.asset,
        'payTo': terms.pay_to, 'amount': str(terms.atomic_amount + 1),
    }
    try:
        validate_selected_requirements(deliberately_incorrect, terms)
    except PaymentTermsMismatch as exc:
        return {'name': 'price_plus_one_atomic_unit', 'result': 'rejected', 'reason': str(exc),
                'signed': False, 'payment_attempted': False}
    raise LivePreflightError('safety regression: mismatched price unexpectedly accepted')


async def preflight_live_challenge(config: LiveX402Config, *, transport: Any | None = None) -> dict[str, Any]:
    import httpx
    own_client = transport is None
    client = transport or httpx.AsyncClient(timeout=15.0, follow_redirects=False, trust_env=False)
    try:
        response = await client.request(config.method, config.endpoint, json=config.json_body)
        # We do not follow redirect; x402 sdk also needs a vetted final URL.
        body = response.content
        return examine_challenge(response.status_code, response.headers, body, config.terms())
    finally:
        if own_client:
            await client.aclose()
