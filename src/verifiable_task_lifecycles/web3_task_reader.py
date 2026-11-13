"""Read-only adapter for LifecycleTracker.getInstance/getTransition.

Requires the optional `web3` dependency. No wallet key, model credentials, or
payment authorization is needed. The caller chooses a trusted RPC and contract.
"""

from __future__ import annotations

from .committed_verifier import LedgerInstance, LedgerTransition
from .model import TaskState
from .deployed_contract_profile import DEPLOYED_LEGACY_READ_ABI, contract_profile

LIFECYCLE_READ_ABI = [
    {
        "type": "function", "name": "getInstance", "stateMutability": "view",
        "inputs": [{"name": "instanceId", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "tuple", "components": [
            {"name": "intentHash", "type": "bytes32"},
            {"name": "modelHash", "type": "bytes32"},
            {"name": "policyHash", "type": "bytes32"},
            {"name": "state", "type": "uint8"},
            {"name": "transitionCount", "type": "uint64"},
            {"name": "creator", "type": "address"},
        ]}],
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


class Web3TaskReader:
    def __init__(
        self, *, rpc_url: str, contract_address: str,
        expected_chain_id: int = 84532,
    ):
        from web3 import Web3

        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        chain_id = self.w3.eth.chain_id
        if chain_id != expected_chain_id:
            raise ValueError(f"RPC chain ID {chain_id} does not match expected {expected_chain_id}")
        address = Web3.to_checksum_address(contract_address)
        code = self.w3.eth.get_code(address)
        if not code:
            raise ValueError("no contract code at supplied lifecycle address")
        self.contract_profile = contract_profile(self.w3, address, code)
        abi = DEPLOYED_LEGACY_READ_ABI if self.contract_profile == "deployed-legacy" else LIFECYCLE_READ_ABI
        self.contract = self.w3.eth.contract(address=address, abi=abi)
        # All reads of one task use the same chain snapshot.  Without this,
        # later transitions/finalization might race with verification.
        self.block_number = int(self.w3.eth.block_number)

    @staticmethod
    def _id(value: str) -> bytes:
        raw = bytes.fromhex(value.removeprefix("0x"))
        if len(raw) != 32:
            raise ValueError("instance_id must be bytes32")
        return raw

    @staticmethod
    def _hex32(value: bytes) -> str:
        return "0x" + bytes(value).hex()

    def get_instance(self, instance_id: str) -> LedgerInstance:
        function = (
            self.contract.functions.instances(self._id(instance_id))
            if getattr(self, "contract_profile", "source") == "deployed-legacy"
            else self.contract.functions.getInstance(self._id(instance_id))
        )
        result = function.call(block_identifier=self.block_number)
        return LedgerInstance(
            intent_hash=self._hex32(result[0]),
            model_hash=self._hex32(result[1]),
            policy_hash=self._hex32(result[2]),
            state=TaskState(result[3]),
            transition_count=int(result[4]),
            creator=result[5],
        )

    def get_transition(self, instance_id: str, index: int) -> LedgerTransition:
        function = (
            self.contract.functions.transitions(self._id(instance_id), index)
            if getattr(self, "contract_profile", "source") == "deployed-legacy"
            else self.contract.functions.getTransition(self._id(instance_id), index)
        )
        result = function.call(block_identifier=self.block_number)
        return LedgerTransition(
            previous_state=TaskState(result[0]),
            action_hash=self._hex32(result[1]),
            payment_hash=self._hex32(result[2]),
            evidence_hash=self._hex32(result[3]),
            next_state=TaskState(result[4]),
        )
