"""Step 5: offline tests of exact payment terms, transfer evidence and failure boundaries."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from dataclasses import replace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from verifiable_task_lifecycles.payment_assurance import (
    AuthorizedPaymentTerms, PaymentTermsMismatch, validate_selected_requirements,
    verify_erc20_transfer, _TRANSFER_TOPIC,
)
from verifiable_task_lifecycles.policy import CatalogEntry

TOKEN='0x' + 'a1'*20
TO='0x' + 'b2'*20
PAYER='0x' + 'c3'*20
OTHER='0x' + 'd4'*20
TX='0x' + 'e5'*32
NETWORK='eip155:84532'


def terms():
    return AuthorizedPaymentTerms(NETWORK,TOKEN,TO,20000)


def challenge(**kwargs):
    r=dict(scheme='exact',network=NETWORK,asset=TOKEN,payTo=TO,amount='20000')
    r.update(kwargs)
    return r


def event(amount=20000, *, token=TOKEN, sender=PAYER, recipient=TO):
    def addr_topic(a): return '0x' + '0'*24 + a.lower()[2:]
    return {'address':token, 'topics':[_TRANSFER_TOPIC,addr_topic(sender),addr_topic(recipient)],
            'data': '0x'+f'{amount:064x}'}


class FakeWeb3:
    def __init__(self, logs=None, *, chain=84532, status=1, confirmations=4):
        self.eth=self
        self.chain_id=chain
        self.block_number=110+confirmations-1
        self.receipt={'status':status,'blockNumber':110,'logs':logs if logs is not None else [event()]}
    def get_transaction_receipt(self, reference):
        if reference!=TX: raise RuntimeError('not found')
        return self.receipt


class PaymentRequirementTests(unittest.TestCase):
    def test_expected_terms_permit_exact_challenge(self):
        validate_selected_requirements(challenge(),terms())

    def test_pydantic_like_model_and_address_case(self):
        obj=SimpleNamespace(model_dump=lambda by_alias=False:challenge(asset=TOKEN.upper().replace('0X','0x'),payTo=TO.upper().replace('0X','0x')))
        validate_selected_requirements(obj,terms())

    def test_trusted_conversion_from_catalog(self):
        entry=CatalogEntry('reputation','controlled',2,'http://x',TO,'rep')
        self.assertEqual(AuthorizedPaymentTerms.from_catalog(entry,network=NETWORK,asset=TOKEN,
                          atomic_units_per_budget_unit=10000).atomic_amount,20000)

    def test_mismatched_payment_requirements_all_fail(self):
        cases=[dict(scheme='upto'), dict(network='eip155:8453'),
               dict(asset=OTHER), dict(payTo=OTHER),dict(amount='30000'),
               dict(amount=20001),dict(amount='1.2e4'),dict(amount='-1'),
               dict(amount=True),dict(amount=None),dict(payTo='0xnotanaddress')]
        for changes in cases:
            with self.subTest(changes=changes),self.assertRaises(PaymentTermsMismatch):
                validate_selected_requirements(challenge(**changes),terms())

    def test_invalid_catalog_conversion_rejected(self):
        entry=CatalogEntry('rep','controlled',0,'http://x',TO)
        with self.assertRaises(ValueError):
            AuthorizedPaymentTerms.from_catalog(entry,network=NETWORK,asset=TOKEN,
                                                  atomic_units_per_budget_unit=10000)

    def test_invalid_token_address_rejected(self):
        with self.assertRaises(ValueError):
            AuthorizedPaymentTerms(NETWORK,'USDC',TO,20000)


class TransferCheckTests(unittest.TestCase):
    def check(self, w3=None, *, reference=TX, payer=PAYER, t=None, min_confirmations=1):
        return verify_erc20_transfer(w3 or FakeWeb3(),reference=reference,payer=payer,
                                     expected=t or terms(),min_confirmations=min_confirmations)

    def test_one_matching_transfer_passes(self):
        r=self.check()
        self.assertEqual((r.status,r.observed_amount,r.block_number),('pass',20000,110))

    def test_wrong_asset_payer_recipient_and_amount_fail(self):
        for log in (event(token=OTHER), event(sender=OTHER), event(recipient=OTHER),event(19999)):
            with self.subTest(log=log): self.assertEqual(self.check(FakeWeb3([log])).status,'fail')

    def test_no_matching_event_fails(self):
        self.assertEqual(self.check(FakeWeb3([])).status,'fail')

    def test_multiple_matching_events_fail(self):
        self.assertEqual(self.check(FakeWeb3([event(),event()])).status,'fail')

    def test_failed_transaction_fails(self):
        self.assertEqual(self.check(FakeWeb3(status=0)).status,'fail')

    def test_wrong_chain_fails(self):
        self.assertEqual(self.check(FakeWeb3(chain=1)).status,'fail')

    def test_pending_or_missing_tx_is_unverified(self):
        self.assertEqual(self.check(reference='SIMULATED-NO-SETTLEMENT').status,'unverified')
        self.assertEqual(self.check(reference='0x'+'0'*64).status,'unverified')

    def test_insufficient_confirmations_unverified(self):
        self.assertEqual(self.check(FakeWeb3(confirmations=1),min_confirmations=3).status,'unverified')

    def test_rpc_exception_unverified(self):
        w3=FakeWeb3()
        w3.get_transaction_receipt=lambda _: (_ for _ in ()).throw(ConnectionError('offline'))
        self.assertEqual(self.check(w3).status,'unverified')

    def test_malformed_transfer_event_not_accepted(self):
        log=event(); log['data']='0xzz'
        self.assertNotEqual(self.check(FakeWeb3([log])).status,'pass')

    def test_wrong_atomic_units_fail(self):
        t=replace(terms(),atomic_amount=30000)
        self.assertEqual(self.check(t=t).status,'fail')


if __name__=='__main__': unittest.main()
