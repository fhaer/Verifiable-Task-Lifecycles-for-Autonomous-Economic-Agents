# LifecycleTracker reference contract

The checked-in `src/LifecycleTracker.sol` is a **reference implementation** of task creation, controller authorization, ordered lifecycle transitions, fixed-size Action/Payment/Evidence commitments and terminal finalization. Semantic policy admission remains off-chain.

**Deployed ABI distinction:** The paper's historical Base Sepolia contract at `0xE27e67da9D39aF51D778648E50EE2182C5B2D680` has different public function and event signatures from this source. Its compiled build metadata was not retained, so this source must **not** be claimed as a byte-for-byte reproduction of that deployment. The Python code pins the historical runtime bytecode hash and supplies the correct deployed getters/write ABI in `src/verifiable_task_lifecycles/deployed_contract_profile.py`. See [Provenance](../docs/PROVENANCE.md).

With Foundry installed, run tests from this directory:

```bash
forge test
```
