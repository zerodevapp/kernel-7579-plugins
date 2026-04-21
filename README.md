# Kernel 7579 Plugins

ERC-7579 modules for [Kernel](https://github.com/zerodevapp/kernel).

## Modules

| Module | Type(s) | Purpose |
|---|---|---|
| [`ECDSAValidator`](src/validators/ECDSAValidator.sol) | 1 / 4 / 7 / 10 | Single-owner ECDSA validator with owner-only `preCheck` |
| [`WebAuthnValidator`](src/validators/WebAuthnValidator.sol) | 1 | P256/WebAuthn validator |
| [`CallerPolicy`](src/policies/CallerPolicy.sol) | 5 / 10 | Per-`(id, wallet)` caller allowlist |
| [`TimelockPolicy`](src/policies/TimelockPolicy.sol) | 5 / 7 / 10 | Proposal → delay → execute flow with expiry |
| [`ECDSASigner`](src/signers/ECDSASigner.sol) | 6 / 7 / 10 | Single ECDSA signer per `(id, wallet)` |
| [`WeightedECDSASigner`](src/signers/WeightedECDSASigner.sol) | 6 / 7 / 10 | Weighted guardians with threshold |
| [`WebAuthnSigner`](src/signers/WebAuthnSigner.sol) | 6 | P256/WebAuthn signer |

Module type IDs follow ERC-7579: `1` validator, `4` hook, `5` policy, `6` signer, `7` stateless validator, `10` stateless validator with sender.

## Build & Test

```bash
forge build
forge test
```

## License

MIT
