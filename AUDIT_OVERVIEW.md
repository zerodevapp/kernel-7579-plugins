# Audit Overview – ERC-7579 Plugins

**Scope** `src/policies`, `src/signers`, `src/validators` (WebAuthn excluded) **Rev** 1.2 **Date** 2025-11-06

**Module IDs** 1 `VALIDATOR`, 2 `EXECUTOR` (unused), 3 `FALLBACK` (unused), 4 `HOOK`, 5 `POLICY`, 6 `SIGNER`, 7 `STATELESS_VALIDATOR`, 8 `STATELESS_VALIDATOR_WITH_SENDER`. Modules only claim IDs they fully implement.

**Policies**
- SignaturePolicy — types 5/10; tracks caller allowlists per `(id, wallet)`; stateless helper expects caller list in calldata.
- TimelockPolicy — types 5/7/10; proposal → execute flow with delay/expiry; detects no-op calldata; proposals keyed by `(account, calldata hash, nonce)`.

**Signers**
- ECDSASigner — types 6/7/10; one signer per `(id, wallet)`; eth-signed fallback; stateless helpers take signer address from calldata.
- WeightedECDSASigner — types 6/7/10; weighted guardians + threshold; enforces ascending signer order; stateless helper uses supplied guardian data.

**Validators**
- ECDSAValidator — types 1/4/7/10; single owner per account; `preCheck` enforces owner-only execution; stateless helpers take owner from calldata.