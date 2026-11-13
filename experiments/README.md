# Archived experiment evidence

These files preserve the observations used by the paper and its subsequent verifier/payment evaluations. Historical results and journals should not be overwritten.

| Directory | Purpose |
|---|---|
| `controlled_cases/` | T1–T6 admission and tampering cases |
| `live_base_sepolia/` | Five controlled runs, eight paid transitions, 18 lifecycle transactions (RQ3 sample) |
| `independent_verification/` | Original two-transition structural and receipt verification (historical RQ2) |
| `external_interop/` | Historical independently operated x402 service interaction |
| `admission_replay/` | Later **on-chain** admission-replay counterexample: structural pass, policy fail at transition 1; synthetic Payment/Evidence |
| `live_x402/` | Separate real testnet x402 request and independently checked ERC-20 transfer |
| `environment/` | Public environment and version information |

For precise scientific claims and ABI provenance, see [Provenance](../docs/PROVENANCE.md) and [Claim-to-artifact map](../docs/CLAIM_ARTIFACT_MAP.md). For verification commands, see [Reproducibility](../docs/REPRODUCIBILITY.md).
