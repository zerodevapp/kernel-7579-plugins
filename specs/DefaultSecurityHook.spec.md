---
title: DefaultSecurityHook — Spec (Invariants / FV trust surface)
project: kernel-7579-plugins
contract: src/hooks/DefaultSecurityHook.sol
branch: feat/restore-dropped-modules
author: taek <leekt216@gmail.com>
---

# DefaultSecurityHook — Invariants (FV trust surface)

> Confirmed by taek on 2026-07-14 via /fv-invariants. This is the trust surface for
> formal verification — sc-formal-verify proves code against THESE claims, nothing else.
> Written to the repo-local `specs/` because `~/Documents/Obsidian` was TCC-blocked from
> the session; sync into `projects/kernel-7579-plugins/specs/` when Documents access is granted.

## Trusted assumptions (named preconditions)

All invariants below hold only within these boundaries, confirmed in the completeness pass:

- **P1 — Honest account.** The ERC-7579 account invokes `preCheck` before executing the
  batch/single call and aborts the execution if `preCheck` reverts. A non-conforming account
  that skips or ignores the hook bypasses every invariant here. (Off-chain / account-implementation trust.)
- **P2 — Standard execute calldata layout.** `preCheck` decodes `msgData` as
  `execute(bytes32 mode, bytes executionData)` via a hardcoded offset (`:112-131`). A different
  entrypoint calldata shape mis-decodes; invariants assume the standard layout.
- **P3 — Honest `isModuleType`.** Module detection (`INV-04`) assumes targets implement
  `isModuleType` truthfully. Adversarial bytecode that reverts/lies is out of scope — see SG-B.

## Invariants

### INV-01 — Blocked token-transfer selectors always revert (unless allowlisted)
A non-allowlisted call carrying any of the 10 blocked ERC-20/721/1155 transfer/approval selectors
reverts `TokenTransferNotAllowed(target, selector)`.
- **Severity:** Critical
- **Source:** code `src/hooks/DefaultSecurityHook.sol:204,214-219` / FV `DSH-ALLOW-01`
- **Form:** observable outcome (exact iff over symbolic `bytes4`; oracle = 10 spec hex literals enumerated independently of `_isBlockedSelector`)
- **Preconditions / trusted assumptions:** P1, P2
- **Out of FV scope?:** no — **double-proven, TCB-independent** (Halmos + Certora; shared residual solc 0.8.30 via_ir)

### INV-02 — Delegatecall execution always reverts
Any execution whose call type is `CALLTYPE_DELEGATECALL` reverts `DelegateCallNotAllowed` in `preCheck`.
- **Severity:** High
- **Source:** code `:117-119`
- **Form:** observable outcome
- **Preconditions / trusted assumptions:** P1, P2
- **Out of FV scope?:** no

### INV-03 — Self-call reverts
A non-allowlisted call whose `target == msg.sender` (the account) reverts `SelfCallNotAllowed`.
- **Severity:** High
- **Source:** code `:193`
- **Form:** observable outcome
- **Preconditions / trusted assumptions:** P1, P2
- **Out of FV scope?:** no

### INV-04 — Call to a module-typed target reverts
A non-allowlisted call to a target for which the `isModuleType` staticcall succeeds reverts
`ModuleCallNotAllowed(target)`.
- **Severity:** High
- **Source:** code `:196,208-212` / FV `DSH-DENY-MODULE-01`
- **Form:** observable outcome (conditional deny branch only)
- **Preconditions / trusted assumptions:** P1, P2, **P3** (heuristic soundness is SG-B, NOT covered by this proof)
- **Out of FV scope?:** no (branch); soundness of the heuristic itself → SG-B (out of scope)

### INV-05 — ETH transfer to non-allowlisted target reverts
A non-allowlisted, non-self, non-module call with `value > 0` reverts `ETHTransferNotAllowed(target, value)`.
- **Severity:** Medium
- **Source:** code `:199` / FV `DSH-DENY-ETH-01::symbolic-target`
- **Form:** observable outcome
- **Preconditions / trusted assumptions:** P1, P2
- **Out of FV scope?:** no — proven (symbolic target concretizes to deployed code; codeless targets excluded by the contract itself)

### INV-06 — Allowlisted (target, selector) bypasses every deny check
If `(msg.sender, target)` is allowlisted and either `allSelectorsAllowed` or the call selector is
in the allowed set, `_checkCall` returns without reverting — no deny check fires.
- **Severity:** High
- **Source:** code `:187-190`
- **Form:** observable outcome (converse of INV-01; proven allowlisted-never-reverts leg of DSH-ALLOW-01)
- **Preconditions / trusted assumptions:** P1, P2
- **Out of FV scope?:** no

### INV-07 — Install lifecycle: double-install reverts; management gated on init
`onInstall` on an already-initialized account reverts `AlreadyInitialized`; `setAllowlist` /
`removeAllowlist` revert `Unauthorized` when the caller is not initialized.
- **Severity:** High
- **Source:** code `:79,154,160` / FV legs (a) `DSH-INSTALL-DOUBLE-01`, (b,c) `check_{Set,Remove}AllowlistRevertsWhenUninitialized`
- **Form:** observable outcome
- **Preconditions / trusted assumptions:** none
- **Out of FV scope?:** no — proven (leg a double-install; legs b,c management-gating)
- **Leg (d) — `onUninstall` NotInitialized guard** (`:93`): the symmetric guard that `onUninstall`
  on a non-initialized account reverts `NotInitialized`. **Severity Low; Out of FV scope = yes (accepted,
  not proven, taek 2026-07-14).** Below the bar where a proof earns its keep — caller is the account,
  a broken guard deletes already-empty state (no attacker gain). Trivially provable from the
  double-install template if ever wanted. See report SG-G.

### INV-08 — Uninstall clears all state; no stale-selector leak on re-install
After `onUninstall`, no target remains allowlisted for the account, and no previously-allowed
selector survives to be honored after a later re-install (S-01 stale-selector + S-03 target-cleanup fix).
- **Severity:** High
- **Source:** code `:92-104,229-256` / FV `DSH-REMOVE-ALLOWLIST-01` / Certora S01/S02/S03
- **Form:** observable outcome (removal restores deny; re-set clears stale selectors)
- **Preconditions / trusted assumptions:** none
- **Out of FV scope?:** no

### INV-09 — Batch: every element is checked through the real decoder
In a `CALLTYPE_BATCH` execution, `_checkCall` runs on every decoded element; the batch reverts if
any element would revert on the single path — the real `decodeBatch`/`getExecution` calldata decode
introduces no bypass.
- **Severity:** Medium
- **Source:** code `:136-141` / FV `DSH-BATCH-DECODER-01`
- **Form:** observable outcome (iff proven in both directions through the real decoder; closes the
  prior Certora `Call[]`-struct-model caveat — decode path now inside the proof, not the TCB)
- **Preconditions / trusted assumptions:** P1, P2
- **Out of FV scope?:** no — proven (coverage bound: batch length concrete at 2, element values/selectors symbolic)

## Out-of-FV-scope (recorded, accepted — not proof gaps)

Naming these is the honest analog of "to be end-to-end you'd have to verify everything." Each was
explicitly accepted by taek on 2026-07-14; none is a covering-claim failure.

- **SG-A (Medium) — blocklist non-exhaustive.** The 10 blocked selectors do not include ERC-777
  `send`, `transferAndCall` (`0x4000aea0`), EIP-3009 `transferWithAuthorization` (`0xe3ee160e`), or
  permit-based pulls — all pass the hook. "Did we enumerate every dangerous selector" is not
  FV-decidable. **Accepted as documented scope** (best-effort blocklist; allowlisting is the real
  protection). Revisit spec §4.8 + re-run /fv-invariants if the blocklist is expanded.
- **SG-B (Medium) — `_isModule` heuristic soundness.** A target whose `isModuleType` reverts
  bypasses the module gate; a benign contract with a permissive fallback is DoS'd. Depends on
  arbitrary external bytecode — not FV-decidable. **Accepted; routed to sc-invariant-fuzz-tester**
  with adversarial target mocks. INV-04 proves only the conditional branch, not the heuristic.
- **SG-C — flows the hook never sees.** ERC-2612/Permit2/ERC-1271 signature approvals, pre-existing
  token approvals, inbound `receive()`/`fallback()` ETH, and `executeFromExecutor` routing are
  invisible to `preCheck`. No hook-level covering claim possible. **Accepted trust model** (spec §11.1).
- **SG-D (Low) — blanket-allowlist self/module defeats all protections.** The allowlist-first return
  at `:188` precedes every deny check, so allowlisting the account itself or a module with empty
  selectors disables protection. **Accepted by design** (owner-trust boundary, spec §5.2/§11.3).
