# Standalone live x402 payment experiment

`first_payment.json` is the preserved result of one successful Base Sepolia x402 v2 `exact` payment to the external sanctions-screening provider, with a locally evaluated one-atomic-unit price-mismatch control and independent ERC-20 transfer verification.

Transfer transaction: `0x2024b3394feec473355f55a08ed318a20b107a8387216e9d42b3a749508f575c`; expected/observed amount: 10,000 atomic units of Circle test USDC (0.01 test USDC). This is a **standalone** test, not a paid transition committed in the adversarial lifecycle. The journal does not contain signing keys. For preflight and read-only audit commands, see [Reproducibility](../../docs/REPRODUCIBILITY.md#standalone-x402-payment-test).
