"""SDK transport doubles verify pre-signing guard and no duplicate paid retries."""
from __future__ import annotations

import asyncio
import base64
import json
import sys
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from verifiable_task_lifecycles.payment_assurance import AuthorizedPaymentTerms, PaymentTermsMismatch
from verifiable_task_lifecycles.x402_client import (
    X402PaymentClient,PaymentOutcomeUncertain,ServiceResponseFailedAfterSettlement,
)

TOKEN='0x'+'a1'*20
TO='0x'+'b2'*20
TX='0x'+'ab'*32
TERMS=AuthorizedPaymentTerms('eip155:84532',TOKEN,TO,10000)


def header(body): return base64.b64encode(json.dumps(body).encode()).decode()


class FakeHttp:
    behaviors=[]
    requests=0
    signatures=0
    def __init__(self,client): self.client=client
    async def __aenter__(self): return self
    async def __aexit__(self,*_): return False
    async def request(self,*,method,url,json):
        type(self).requests+=1
        behavior=type(self).behaviors.pop(0)
        context=SimpleNamespace(selected_requirements=behavior.get('requirements',{
            'scheme':'exact','network':TERMS.network,'asset':TERMS.asset,
            'payTo':TERMS.pay_to,'amount':str(TERMS.atomic_amount)
        }))
        result=self.client.hook(context)
        if result is not None:
            raise RuntimeError(f'SDK payment authorization aborted: {result.reason}')
        type(self).signatures+=1
        if behavior.get('transport_error'):
            raise ConnectionError('request timed out after payment attempt')
        return FakeResponse(behavior)


class FakeResponse:
    def __init__(self,beh):
        self.status_code=beh.get('status',200)
        self.headers={}
        if not beh.get('no_header'):
            self.headers['PAYMENT-RESPONSE']=header(beh.get('settlement',{
                'success':True,'transaction':TX,'network':TERMS.network,'payer':'0x'+'ef'*20
            }))
        self.text='service unavailable'
    async def aread(self): return b''
    def json(self): return {'result':'ok'}


class FakeClient:
    def on_before_payment_creation(self,callback): self.hook=callback


class X402GuardTests(unittest.TestCase):
    def setUp(self):
        FakeHttp.behaviors=[]; FakeHttp.requests=0; FakeHttp.signatures=0
        sdk=types.ModuleType('x402')
        sdk.AbortResult=lambda reason: SimpleNamespace(reason=reason)
        transport=types.ModuleType('x402.http.clients'); transport.x402HttpxClient=FakeHttp
        pkg=types.ModuleType('x402.http'); pkg.clients=transport
        mocks={'x402':sdk,'x402.http':pkg,'x402.http.clients':transport}
        patcher=patch.dict(sys.modules,mocks);patcher.start();self.addCleanup(patcher.stop)
        self.client=X402PaymentClient.__new__(X402PaymentClient)
        self.client._payer='0x'+'ef'*20
        self.client._new_client=lambda: FakeClient()

    def run_request(self, **kwargs):
        FakeHttp.behaviors.append(kwargs)
        return asyncio.run(self.client.request('GET','http://example.invalid/paid',terms=TERMS))

    def test_valid_signs_once_and_returns_result(self):
        p=self.run_request()
        self.assertEqual(p.transaction,TX)
        self.assertEqual(FakeHttp.signatures,1)
        self.assertEqual(FakeHttp.requests,1)

    def test_mismatch_rejected_before_signing(self):
        with self.assertRaises(PaymentTermsMismatch):
            self.run_request(requirements={'scheme':'exact','network':TERMS.network,
                                          'asset':TOKEN,'payTo':TO,'amount':'11000'})
        self.assertEqual(FakeHttp.signatures,0)

    def test_service_failed_after_reported_settlement_no_retry(self):
        with self.assertRaises(ServiceResponseFailedAfterSettlement) as cm:
            self.run_request(status=503)
        self.assertEqual(cm.exception.transaction,TX)
        self.assertEqual(FakeHttp.requests,1)
        self.assertEqual(FakeHttp.signatures,1)

    def test_timeout_after_authorization_unknown_and_no_retry(self):
        with self.assertRaises(PaymentOutcomeUncertain):
            self.run_request(transport_error=True)
        self.assertEqual(FakeHttp.requests,1)
        self.assertEqual(FakeHttp.signatures,1)

    def test_missing_settlement_header_is_uncertain(self):
        with self.assertRaises(PaymentOutcomeUncertain):
            self.run_request(no_header=True)
        self.assertEqual(FakeHttp.requests,1)

    def test_failed_settlement_report_is_uncertain(self):
        with self.assertRaises(PaymentOutcomeUncertain):
            self.run_request(settlement={'success':False,'network':TERMS.network})
        self.assertEqual(FakeHttp.requests,1)

    def test_reported_settlement_payer_must_match_signer(self):
        with self.assertRaises(PaymentOutcomeUncertain):
            self.run_request(settlement={
                "success":True,"transaction":TX,"network":TERMS.network,
                "payer":"0x"+"11"*20,
            })

    def test_no_trusted_terms_rejected_before_transport(self):
        with self.assertRaises(ValueError):
            asyncio.run(self.client.request('GET','http://example.invalid',terms=None))
        self.assertEqual(FakeHttp.requests,0)


if __name__=='__main__':unittest.main()
