"""Mocked tx transport for the Step 4 testnet recorder; no RPC, signing, or funds."""

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from verifiable_task_lifecycles.web3_experiment_recorder import (
    ExperimentRecordingError, Web3ExperimentRecorder,
)


class MockFunction:
    def __init__(self, *, capture, data=None, is_tx=False):
        self.capture = capture
        self.data = data
        self.is_tx = is_tx

    def call(self, opts=None, block_identifier=None):
        if self.is_tx:
            self.capture["preflight"] = opts
            if self.capture.get("preflight_reverts"):
                raise RuntimeError("contract revert")
        return self.data

    def build_transaction(self, options):
        self.capture["tx_options"] = options
        return {"nonce": options["nonce"], "chainId": options["chainId"]}


class MockFunctions:
    def __init__(self, capture, instance_data, transition_data):
        self.capture = capture
        self.instance_data = instance_data
        self.transition_data = transition_data

    def getInstance(self, instance_id):
        self.capture["get_instance"] = instance_id
        val = self.instance_data
        if self.capture.get("during_readback"):
            val = self.capture.get("bad_readback", val)
        return MockFunction(capture=self.capture, data=val)

    def getTransition(self, instance_id, index):
        self.capture["get_transition"] = index
        return MockFunction(capture=self.capture, data=self.transition_data)

    def recordTransition(self, *values):
        self.capture["record_args"] = values
        return MockFunction(capture=self.capture, is_tx=True)


class MockWeb3:
    def __init__(self, capture):
        self.capture = capture
        self.eth = SimpleNamespace(
            chain_id=84532,
            get_transaction_count=lambda address, kind: 9,
            account=SimpleNamespace(sign_transaction=self.sign),
            send_raw_transaction=self.send,
            wait_for_transaction_receipt=self.wait,
        )

    def sign(self, tx, key):
        self.capture["signed"] = tx
        return SimpleNamespace(raw_transaction=b"signed")

    def send(self, raw):
        self.capture["sent"] = raw
        return bytes.fromhex("ab" * 32)

    def wait(self, tx_hash, timeout):
        if self.capture.get("timeout"):
            raise TimeoutError("receipt not available")
        self.capture["during_readback"] = True
        return {"status": self.capture.get("status", 1), "blockNumber": 987}

    def to_hex(self, value):
        return "0x" + value.hex()


class Web3ExperimentRecorderTests(unittest.TestCase):
    def setUp(self):
        self.capture = {}
        self.addr = "0x" + "33" * 20
        self.values = [bytes.fromhex(ch * 64) for ch in "1234"]
        self.instance_data = [self.values[1], self.values[2], self.values[3], 1, 0, self.addr]
        self.transition_data = [1, self.values[1], self.values[2], self.values[3], 1]

    def recorder(self, *, expected_index=0):
        self.instance_data[4] = expected_index
        rec = object.__new__(Web3ExperimentRecorder)
        rec.account = SimpleNamespace(address=self.addr, key=b"test-only-key")
        rec.w3 = MockWeb3(self.capture)
        rec.confirmation_timeout = 60
        # Correct count AFTER recording for readback; mocking separately.
        funcs = MockFunctions(self.capture, self.instance_data, self.transition_data)
        original = funcs.getInstance
        def get_instance(instance_id):
            if self.capture.get("during_readback"):
                valid = list(self.instance_data)
                valid[4] = expected_index + 1
                if self.capture.get("bad_readback") is not None:
                    valid = self.capture["bad_readback"]
                return MockFunction(capture=self.capture, data=valid)
            return original(instance_id)
        funcs.getInstance = get_instance
        rec.contract = SimpleNamespace(functions=funcs)
        return rec

    def send(self, rec, *, expected_index=0, action_hash=None):
        return rec.record_transition(
            instance_id="0x" + self.values[0].hex(),
            expected_index=expected_index,
            action_hash=action_hash or "0x" + self.values[1].hex(),
            payment_hash="0x" + self.values[2].hex(),
            evidence_hash="0x" + self.values[3].hex(),
        )

    def test_confirmed_transition_checks_contract_readback(self):
        txid = self.send(self.recorder())
        self.assertEqual(txid, "0x" + "ab" * 32)
        self.assertEqual(self.capture["record_args"][1], 1)
        self.assertEqual(self.capture["record_args"][-1], 1)
        self.assertEqual(self.capture["record_args"][2], self.values[1])
        self.assertEqual(self.capture["sent"], b"signed")
        self.assertEqual(self.capture["get_transition"], 0)

    def test_rejects_invalid_or_zero_commitment_before_send(self):
        with self.assertRaises(ValueError):
            self.send(self.recorder(), action_hash="0x" + "00" * 32)
        self.assertNotIn("sent", self.capture)

    def test_rejects_wrong_transition_count_before_send(self):
        rec = self.recorder(expected_index=1)
        with self.assertRaisesRegex(ExperimentRecordingError, "transition count"):
            self.send(rec, expected_index=0)
        self.assertNotIn("sent", self.capture)

    def test_rejects_wrong_creator_before_send(self):
        rec = self.recorder()
        self.instance_data[5] = "0x" + "44" * 20
        with self.assertRaisesRegex(ExperimentRecordingError, "not the task's creator"):
            self.send(rec)
        self.assertNotIn("sent", self.capture)

    def test_rejects_terminal_state_before_send(self):
        rec = self.recorder()
        self.instance_data[3] = 2
        with self.assertRaisesRegex(ExperimentRecordingError, "not active"):
            self.send(rec)
        self.assertNotIn("sent", self.capture)

    def test_contract_preflight_revert_prevents_submission(self):
        self.capture["preflight_reverts"] = True
        with self.assertRaisesRegex(ExperimentRecordingError, "preflight reverted"):
            self.send(self.recorder())
        self.assertNotIn("sent", self.capture)

    def test_reverted_transaction_reported(self):
        self.capture["status"] = 0
        with self.assertRaisesRegex(ExperimentRecordingError, "reverted"):
            self.send(self.recorder())

    def test_timeout_reports_unknown_tx_without_retry(self):
        self.capture["timeout"] = True
        with self.assertRaisesRegex(ExperimentRecordingError, "DO NOT RETRY") as ctx:
            self.send(self.recorder())
        self.assertIn("ab" * 32, str(ctx.exception))
        self.assertEqual(self.capture["sent"], b"signed")

    def test_wrong_recorded_commitment_fails_confirmation(self):
        self.transition_data[2] = bytes.fromhex("ee" * 32)
        with self.assertRaisesRegex(ExperimentRecordingError, "do not match"):
            self.send(self.recorder())

    def test_wrong_readback_count_fails_confirmation(self):
        bad = list(self.instance_data)
        bad[4] = 99
        self.capture["bad_readback"] = bad
        with self.assertRaisesRegex(ExperimentRecordingError, "do not match"):
            self.send(self.recorder())

    def test_must_use_one_of_two_indices(self):
        with self.assertRaises(ValueError):
            self.send(self.recorder(), expected_index=3)


if __name__ == "__main__":
    unittest.main()
