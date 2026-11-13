"""Pinned ABI for the archived Base Sepolia LifecycleTracker deployment.

The checked-in Solidity source has *different public getter names, a different
recordTransition signature and event schema* than this older deployed contract.
Treat the observed bytecode hash as a safety boundary before signing writes.
"""

from __future__ import annotations

DEPLOYED_LEGACY_ADDRESS = "0xE27e67da9D39aF51D778648E50EE2182C5B2D680"
DEPLOYED_LEGACY_CHAIN_ID = 84532
DEPLOYED_LEGACY_RUNTIME_KECCAK = (
    "0x48eae3831745a93d12578aeafb60bdde0e9c62f76ec54cd5a45f526679be71e5"
)

# Solidity's public mapping getter returns six flat ABI words rather than a
# single tuple. State order: None=0, Active=1, Completed=2, Failed=3, Revoked=4.
DEPLOYED_LEGACY_READ_ABI = [
    {
        "type": "function", "name": "instances", "stateMutability": "view",
        "inputs": [{"name": "instanceId", "type": "bytes32"}],
        "outputs": [
            {"name": "intentHash", "type": "bytes32"},
            {"name": "modelHash", "type": "bytes32"},
            {"name": "policyHash", "type": "bytes32"},
            {"name": "state", "type": "uint8"},
            {"name": "transitionCount", "type": "uint64"},
            {"name": "creator", "type": "address"},
        ],
    },
    {
        "type": "function", "name": "transitions", "stateMutability": "view",
        "inputs": [
            {"name": "instanceId", "type": "bytes32"},
            {"name": "transitionNo", "type": "uint64"},
        ],
        "outputs": [
            {"name": "previousState", "type": "uint8"},
            {"name": "actionHash", "type": "bytes32"},
            {"name": "paymentHash", "type": "bytes32"},
            {"name": "evidenceHash", "type": "bytes32"},
            {"name": "nextState", "type": "uint8"},
        ],
    },
]

DEPLOYED_LEGACY_WRITES_ABI = [
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
        "type": "function", "name": "recordTransition", "stateMutability": "nonpayable",
        # Verified selector 0xc02f1f24 (NOT the checked-in source selector 0x562543c8)
        "inputs": [
            {"name": "instanceId", "type": "bytes32"},
            {"name": "actionHash", "type": "bytes32"},
            {"name": "paymentHash", "type": "bytes32"},
            {"name": "evidenceHash", "type": "bytes32"},
            {"name": "nextState", "type": "uint8"},
        ],
        "outputs": [],
    },
]

DEPLOYED_LEGACY_ABI = DEPLOYED_LEGACY_READ_ABI + DEPLOYED_LEGACY_WRITES_ABI


def contract_profile(w3, address: str, code: bytes) -> str:
    """Identify known deployed contract; refuse unknown bytecode at its address.

    Other addresses remain `source` profiles for the checked-in Solidity API.
    This function performs no network reads, signing, or writes.
    """
    if address.lower() != DEPLOYED_LEGACY_ADDRESS.lower():
        return "source"
    if int(w3.eth.chain_id) != DEPLOYED_LEGACY_CHAIN_ID:
        raise ValueError("the archived deployment address requires Base Sepolia")
    digest = w3.to_hex(w3.keccak(code)).lower()
    if digest != DEPLOYED_LEGACY_RUNTIME_KECCAK:
        raise ValueError(
            "unexpected runtime code at archived lifecycle address: " + digest
        )
    return "deployed-legacy"
