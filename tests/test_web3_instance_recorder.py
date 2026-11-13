"""Exercise the live-transport adapter without network access or private keys."""

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from verifiable_task_lifecycles.task_creation import TaskCreationError
from verifiable_task_lifecycles.web3_instance_recorder import Web3InstanceRecorder


class MockTx:
    def __init__(self, capture):
        self.capture = capture
    def build_transaction(self, tx_options):
        self.capture["tx_options"] = tx_options
        return {"nonce": tx_options["nonce"], "chainId": tx_options["chainId"]}


class MockFunctions:
    def __init__(self, capture, readback):
        self.capture = capture
        self.readback = readback
    def createInstance(self, *args):
        self.capture["create_args"] = args
        return MockTx(self.capture)
    def getInstance(self, instance_id):
        self.capture["get_id"] = instance_id
        return SimpleNamespace(call=lambda: self.readback)


class MockWeb3:
    def __init__(self, capture, status):
        self.capture = capture
        self.status = status
        self.eth = SimpleNamespace(
            chain_id=84532,
            get_transaction_count=lambda address, kind: 10,
            account=SimpleNamespace(sign_transaction=self.sign),
            send_raw_transaction=self.send,
            wait_for_transaction_receipt=self.wait,
        )
    def sign(self, tx, private_key):
        self.capture["signed"] = tx
        return SimpleNamespace(raw_transaction=b"signed")
    def send(self, raw):
        self.capture["sent"] = raw
        return b"hash"
    def wait(self, tx_hash, timeout):
        self.capture["waited"] = tx_hash
        return {"status": self.status}
    def to_hex(self, raw):
        return "0x" + "ae" * 32


class Web3RecorderTests(unittest.TestCase):
    def setUp(self):
        self.capture = {}
        self.account = SimpleNamespace(address="0x" + "12" * 20, key=b"key")
        self.instance_id = "0x" + "01" * 32
        self.intent_hash = "0x" + "02" * 32
        self.model_hash = "0x" + "03" * 32
        self.policy_hash = "0x" + "04" * 32
        self.readback = [
            bytes.fromhex(self.intent_hash[2:]),
            bytes.fromhex(self.model_hash[2:]),
            bytes.fromhex(self.policy_hash[2:]),
            1, 0, self.account.address,
        ]

    def recorder(self, *, status=1, readback=None):
        obj = object.__new__(Web3InstanceRecorder)
        obj.w3 = MockWeb3(self.capture, status)
        obj.account = self.account
        obj.contract = SimpleNamespace(
            functions=MockFunctions(self.capture, self.readback if readback is None else readback)
        )
        obj.confirmation_timeout = 60
        return obj

    def create(self, recorder):
        return recorder.create_instance(
            instance_id=self.instance_id,
            intent_hash=self.intent_hash,
            model_hash=self.model_hash,
            policy_hash=self.policy_hash,
        )

    def test_adapter_passes_expected_bytes32_and_confirms_onchain_state(self):
        tx_hash = self.create(self.recorder())
        self.assertEqual(tx_hash, "0x" + "ae" * 32)
        self.assertEqual(self.capture["create_args"][0], bytes.fromhex("01" * 32))
        self.assertEqual(self.capture["create_args"][3], bytes.fromhex("04" * 32))
        self.assertEqual(self.capture["get_id"], bytes.fromhex("01" * 32))
        self.assertEqual(self.capture["sent"], b"signed")

    def test_adapter_rejects_reverted_transaction(self):
        with self.assertRaisesRegex(TaskCreationError, "reverted"):
            self.create(self.recorder(status=0))
        self.assertNotIn("get_id", self.capture)

    def test_adapter_rejects_mismatched_contract_commitment(self):
        bad = list(self.readback)
        bad[2] = bytes.fromhex("ee" * 32)
        with self.assertRaisesRegex(TaskCreationError, "does not match prepared commitments"):
            self.create(self.recorder(readback=bad))

    def test_adapter_rejects_invalid_bytes32(self):
        with self.assertRaises(ValueError):
            self.recorder().create_instance(
                instance_id=self.instance_id,
                intent_hash="0x1234",
                model_hash=self.model_hash,
                policy_hash=self.policy_hash,
            )
        self.assertNotIn("sent", self.capture)


if __name__ == "__main__":
    unittest.main()
