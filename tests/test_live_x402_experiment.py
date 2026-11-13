from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT / 'scripts'))

from verifiable_task_lifecycles.live_payment_probe import (
    LivePreflightError, LiveX402Config, examine_challenge, check_negative_control,
    preflight_live_challenge,
)
import run_live_x402 as runner

CONFIG = ROOT / 'examples' / 'live_sanctions_testnet.json'


def quote(config, **changes):
    terms = config.terms()
    offer = dict(scheme='exact', network=terms.network, asset=terms.asset,
                 payTo=terms.pay_to, amount=str(terms.atomic_amount))
    offer.update(changes)
    return {'x402Version': 2, 'accepts': [offer]}


def header(quote_obj):
    encoded = base64.b64encode(json.dumps(quote_obj).encode()).decode()
    return {'PAYMENT-REQUIRED': encoded}


class FakeTransport:
    def __init__(self, response):
        self.response = response
        self.calls = 0

    async def request(self, method, url, json):
        self.calls += 1
        return self.response


class LiveX402PreflightTests(unittest.TestCase):
    def setUp(self):
        self.config = LiveX402Config.load(CONFIG)

    def test_catalog_is_pinned_to_archived_external_provider(self):
        terms = self.config.terms()
        self.assertEqual(terms.network, 'eip155:84532')
        self.assertEqual(terms.atomic_amount, 10000)
        self.assertEqual(terms.pay_to.lower(), '0xb3e7993ed2fc2c79fff220620240f298bba9bf5b')

    def test_header_v2_exact_terms_pass(self):
        result=examine_challenge(402, header(quote(self.config)), b'', self.config.terms())
        self.assertTrue(result['exact_match'])
        self.assertEqual(result['observed_quote_price_mismatch_control'], 'rejected-without-signing')

    def test_header_is_case_insensitive(self):
        self.assertTrue(examine_challenge(402, {'payment-required':list(header(quote(self.config)).values())[0]},
                                          b'', self.config.terms())['exact_match'])

    def test_price_mismatch_stops_preflight(self):
        with self.assertRaisesRegex(LivePreflightError, 'no payment offer'):
            examine_challenge(402, header(quote(self.config, amount='10001')), b'', self.config.terms())

    def test_asset_recipient_network_mismatch_each_stop(self):
        for diff in ({'asset':'0x'+'ab'*20},{'payTo':'0x'+'bc'*20},{'network':'eip155:8453'},
                     {'scheme':'upto'}):
            with self.subTest(diff=diff), self.assertRaises(LivePreflightError):
                examine_challenge(402, header(quote(self.config, **diff)), b'', self.config.terms())

    def test_http_200_302_404_and_500_fail(self):
        for status in (200, 302, 404, 500):
            with self.subTest(status=status), self.assertRaises(LivePreflightError):
                examine_challenge(status, header(quote(self.config)), b'', self.config.terms())

    def test_v1_and_malformed_alternatives_fail(self):
        for test_obj in ({'x402Version':1,'accepts':quote(self.config)['accepts']},
                         {'x402Version':2,'accepts':[]},
                         {'x402Version':2,'accepts':['bad']}):
            with self.subTest(obj=test_obj), self.assertRaises(LivePreflightError):
                examine_challenge(402, header(test_obj), b'', self.config.terms())

    def test_body_fallback_is_read_only(self):
        data = json.dumps(quote(self.config)).encode()
        self.assertTrue(examine_challenge(402, {}, data, self.config.terms())['exact_match'])

    def test_two_offers_one_matches(self):
        q=quote(self.config)
        bad=dict(q['accepts'][0]); bad['amount']='99999'
        q['accepts'].insert(0,bad)
        result=examine_challenge(402,header(q),b'',self.config.terms())
        self.assertEqual(result['matching_offers'],1)
        self.assertEqual(result['rejected_offer_count'],1)

    def test_negative_control_does_not_sign_or_pay(self):
        result=check_negative_control(self.config.terms())
        self.assertEqual(result['result'],'rejected')
        self.assertFalse(result['signed'])
        self.assertFalse(result['payment_attempted'])

    def test_mock_transport_preflight_one_request(self):
        q=quote(self.config)
        transport=FakeTransport(SimpleNamespace(status_code=402,headers=header(q),content=b''))
        result=asyncio.run(preflight_live_challenge(self.config,transport=transport))
        self.assertEqual(transport.calls,1)
        self.assertTrue(result['exact_match'])

    def test_rejects_non_testnet_or_excessive_price_before_payment(self):
        raw=json.loads(CONFIG.read_text())
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'cfg.json'
            for key, value in (('network','eip155:8453'),('atomic_units_per_budget_unit',10001),
                               ('endpoint','http://example.com/paid')):
                edited=dict(raw); edited[key]=value;path.write_text(json.dumps(edited))
                with self.subTest(key=key),self.assertRaises(LivePreflightError):
                    LiveX402Config.load(path)

    def test_journal_create_exclusive_and_update_without_credentials(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'session.json'
            initial={'status':'initialized','secret':None}
            runner.prepare_journal(path,initial)
            with self.assertRaises(FileExistsError):runner.prepare_journal(path,initial)
            runner.save_journal(path,{'status':'preflight-pass'})
            self.assertEqual(json.loads(path.read_text()),{'status':'preflight-pass'})
            if os.name == 'posix':
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_send_blocked_without_ack_or_journal(self):
        args=SimpleNamespace(config=str(CONFIG),send=True,
                acknowledge_one_testnet_payment=False,journal=None,
                rpc_url='https://sepolia.base.org', min_confirmations=1)
        with self.assertRaises(LivePreflightError):
            asyncio.run(runner.run(args))
        args.acknowledge_one_testnet_payment=True
        with self.assertRaises(LivePreflightError):
            asyncio.run(runner.run(args))


if __name__=='__main__': unittest.main()
