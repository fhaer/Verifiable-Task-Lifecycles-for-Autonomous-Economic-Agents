"""Opt-in Base Sepolia recorder for the Step 4 adversarial lifecycle experiment.

Only creates a lifecycle instance and records the Action/Payment/Evidence
*commitments*. It NEVER invokes x402 or transfers tokens. Only call it with
an explicit user-approved --send invocation and a testnet key.
"""

from __future__ import annotations

import re

from .task_creation import TaskCreationError
from .web3_instance_recorder import LIFECYCLE_CREATION_ABI, Web3InstanceRecorder
from .deployed_contract_profile import DEPLOYED_LEGACY_ABI


class ExperimentRecordingError(RuntimeError):
    """A lifecycle test transaction failed or requires manual reconciliation."""


LIFECYCLE_EXPERIMENT_ABI = LIFECYCLE_CREATION_ABI + [
    {
        "type": "function", "name": "recordTransition", "stateMutability": "nonpayable",
        "inputs": [
            {"name": "instanceId", "type": "bytes32"},
            {"name": "previousState", "type": "uint8"},
            {"name": "actionHash", "type": "bytes32"},
            {"name": "paymentHash", "type": "bytes32"},
            {"name": "evidenceHash", "type": "bytes32"},
            {"name": "nextState", "type": "uint8"},
        ],
        "outputs": [],
    },
    {
        "type": "function", "name": "getTransition", "stateMutability": "view",
        "inputs": [
            {"name": "instanceId", "type": "bytes32"},
            {"name": "transitionNo", "type": "uint64"},
        ],
        "outputs": [{"name": "", "type": "tuple", "components": [
            {"name": "previousState", "type": "uint8"},
            {"name": "actionHash", "type": "bytes32"},
            {"name": "paymentHash", "type": "bytes32"},
            {"name": "evidenceHash", "type": "bytes32"},
            {"name": "nextState", "type": "uint8"},
        ]}],
    },
]


def _bytes32(value: str) -> bytes:
    if not isinstance(value, str) or re.fullmatch(r"(?:0x)?[0-9a-fA-F]{64}", value) is None:
        raise ValueError("commitment must be exactly one bytes32 hexadecimal value")
    result = bytes.fromhex(value.removeprefix("0x"))
    if result == bytes(32):
        raise ValueError("zero bytes32 commitment is not allowed")
    return result


class Web3ExperimentRecorder(Web3InstanceRecorder):
    """The same authorized contract creator signs each transition."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        abi = DEPLOYED_LEGACY_ABI if self.contract_profile == "deployed-legacy" else LIFECYCLE_EXPERIMENT_ABI
        self.contract = self.w3.eth.contract(address=self.contract.address, abi=abi)

    def _get_transition(self, instance_id: bytes, index: int, *, block_number: int):
        function = (
            self.contract.functions.transitions(instance_id, index)
            if getattr(self, "contract_profile", "source") == "deployed-legacy"
            else self.contract.functions.getTransition(instance_id, index)
        )
        return function.call(block_identifier=block_number)

    def record_transition(
        self, *, instance_id: str, expected_index: int,
        action_hash: str, payment_hash: str, evidence_hash: str,
    ) -> str:
        if type(expected_index) is not int or expected_index not in (0, 1):
            raise ValueError("Step 4 has exactly two zero-based transitions")
        values = (
            _bytes32(instance_id), _bytes32(action_hash),
            _bytes32(payment_hash), _bytes32(evidence_hash),
        )
        current = self._get_instance(values[0])
        if int(current[3]) != 1:
            raise ExperimentRecordingError("task is not active; will not send a transition")
        if int(current[4]) != expected_index:
            raise ExperimentRecordingError(
                f"unexpected on-chain transition count {int(current[4])}; "
                "reconcile before any retry"
            )
        if current[5].lower() != self.account.address.lower():
            raise ExperimentRecordingError("configured key is not the task's creator")
        # Both states are Active (1). The contract cannot enforce admission Pi.
        if getattr(self, "contract_profile", "source") == "deployed-legacy":
            # Deployed contract derives previous state internally; five arguments.
            function = self.contract.functions.recordTransition(
                values[0], values[1], values[2], values[3], 1
            )
        else:
            function = self.contract.functions.recordTransition(
                values[0], 1, values[1], values[2], values[3], 1
            )
        try:
            function.call({"from": self.account.address})  # no state change
        except Exception as exc:
            raise ExperimentRecordingError("recordTransition preflight reverted; no tx sent") from exc
        tx = function.build_transaction({
            "from": self.account.address,
            "nonce": self.w3.eth.get_transaction_count(self.account.address, "pending"),
            "chainId": self.w3.eth.chain_id,
        })
        signed = self.w3.eth.account.sign_transaction(tx, self.account.key)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        transaction_id = self.w3.to_hex(tx_hash)
        try:
            receipt = self.w3.eth.wait_for_transaction_receipt(
                tx_hash, timeout=self.confirmation_timeout
            )
        except Exception as exc:
            raise ExperimentRecordingError(
                f"transition transaction {transaction_id} submitted but confirmation "
                "is unknown. DO NOT RETRY before checking the chain"
            ) from exc
        if int(receipt["status"]) != 1:
            raise ExperimentRecordingError(f"transition transaction {transaction_id} reverted")

        try:
            block_no = int(receipt["blockNumber"])
            state = self._get_instance(values[0], block_number=block_no)
            actual = self._get_transition(values[0], expected_index, block_number=block_no)
        except Exception as exc:
            raise ExperimentRecordingError(
                f"confirmed transaction {transaction_id}, but read-back is unavailable; "
                "reconcile before any retry"
            ) from exc
        if (
            int(state[3]) != 1
            or int(state[4]) != expected_index + 1
            or state[5].lower() != self.account.address.lower()
            or int(actual[0]) != 1
            or tuple(bytes(value) for value in actual[1:4]) != values[1:4]
            or int(actual[4]) != 1
        ):
            raise ExperimentRecordingError(
                f"confirmed transaction {transaction_id}, but recorded commitments "
                "do not match; reconcile before retrying"
            )
        return transaction_id
