"""Optional Base Sepolia adapter for LifecycleTracker.createInstance.

Only used on an explicit live submission. Nothing in the deterministic test
suite connects to a network or signs transactions.
"""

from __future__ import annotations

from .task_creation import TaskCreationError
from .deployed_contract_profile import DEPLOYED_LEGACY_ABI, contract_profile

# ABI limited to the two functions used for creation and confirmation.
LIFECYCLE_CREATION_ABI = [
    {
        "type": "function", "name": "createInstance", "stateMutability": "nonpayable",
        "inputs": [
            {"name": "instanceId", "type": "bytes32"},
            {"name": "intentHash", "type": "bytes32"},
            {"name": "modelHash", "type": "bytes32"},
            {"name": "policyHash", "type": "bytes32"},
        ],
        "outputs": [],
    },
    {
        "type": "function", "name": "getInstance", "stateMutability": "view",
        "inputs": [{"name": "instanceId", "type": "bytes32"}],
        "outputs": [
            {"name": "", "type": "tuple", "components": [
                {"name": "intentHash", "type": "bytes32"},
                {"name": "modelHash", "type": "bytes32"},
                {"name": "policyHash", "type": "bytes32"},
                {"name": "state", "type": "uint8"},
                {"name": "transitionCount", "type": "uint64"},
                {"name": "creator", "type": "address"},
            ]},
        ],
    },
]


class Web3InstanceRecorder:
    """Sign, submit, confirm, and read back a task creation on one network."""

    def __init__(
        self, *, rpc_url: str, contract_address: str, private_key: str,
        expected_chain_id: int = 84532, confirmation_timeout: int = 120,
    ):
        from web3 import Web3  # optional dependency (pip install -e '.[live]')

        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        chain_id = self.w3.eth.chain_id
        if chain_id != expected_chain_id:
            raise TaskCreationError(
                f"RPC chain ID {chain_id} does not match required {expected_chain_id}"
            )
        self.account = self.w3.eth.account.from_key(private_key)
        address = Web3.to_checksum_address(contract_address)
        code = self.w3.eth.get_code(address)
        if not code:
            raise TaskCreationError("no contract code at supplied lifecycle address")
        try:
            self.contract_profile = contract_profile(self.w3, address, code)
        except ValueError as exc:
            raise TaskCreationError(str(exc)) from exc
        abi = DEPLOYED_LEGACY_ABI if self.contract_profile == "deployed-legacy" else LIFECYCLE_CREATION_ABI
        self.contract = self.w3.eth.contract(address=address, abi=abi)
        self.confirmation_timeout = confirmation_timeout

    def _get_instance(self, instance_id: bytes, *, block_number: int | None = None):
        function = (
            self.contract.functions.instances(instance_id)
            if getattr(self, "contract_profile", "source") == "deployed-legacy"
            else self.contract.functions.getInstance(instance_id)
        )
        return function.call() if block_number is None else function.call(block_identifier=block_number)

    def create_instance(
        self, *, instance_id: str, intent_hash: str, model_hash: str, policy_hash: str
    ) -> str:
        values = [bytes.fromhex(value.removeprefix("0x")) for value in (
            instance_id, intent_hash, model_hash, policy_hash
        )]
        if any(len(value) != 32 for value in values):
            raise ValueError("contract commitments must be bytes32")
        function = self.contract.functions.createInstance(*values)
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
            raise TaskCreationError(
                f"transaction {transaction_id} submitted; receipt confirmation unavailable. "
                "Check the chain before retrying"
            ) from exc
        if int(receipt["status"]) != 1:
            raise TaskCreationError(f"creation transaction {transaction_id} reverted")

        try:
            block_number = receipt.get("blockNumber")
            actual = self._get_instance(
                values[0], block_number=None if block_number is None else int(block_number)
            )
        except Exception as exc:
            raise TaskCreationError(
                f"transaction {transaction_id} confirmed; could not read back commitments"
            ) from exc
        # Solidity returns (intentHash, modelHash, policyHash, state,
        # transitionCount, creator) in this order.
        if (
            bytes(actual[0]) != values[1]
            or bytes(actual[1]) != values[2]
            or bytes(actual[2]) != values[3]
            or int(actual[3]) != 1
            or int(actual[4]) != 0
            or actual[5].lower() != self.account.address.lower()
        ):
            raise TaskCreationError(
                f"transaction {transaction_id} confirmed but on-chain instance "
                "does not match prepared commitments"
            )
        return transaction_id
