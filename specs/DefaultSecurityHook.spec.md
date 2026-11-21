---
title: DefaultSecurityHook — Spec (Invariants / FV trust surface)
project: kernel-7579-plugins
contract: src/hooks/DefaultSecurityHook.sol
branch: feat/restore-dropped-modules
author: taek <leekt216@gmail.com>
---

# DefaultSecurityHook — Invariants (FV trust surface)

> Confirmed by taek on 2026-07-14 via /fv-invariants and updated on 2026-09-15 for the
> Trail of Bits remediation. This is the trust surface for formal verification:
> sc-formal-verify proves code against these claims, nothing else.

## Trusted assumptions (named preconditions)

All invariants below hold only within these boundaries, confirmed in the completeness pass:

- **P1 — Honest account.** The ERC-7579 account invokes `preCheck` before executing the
  batch/single call and aborts the execution if `preCheck` reverts. A non-conforming account
  that skips or ignores the hook bypasses every invariant here. (Off-chain / account-implementation trust.)
- **P2 — Canonical supported callback calldata.** `preCheck` accepts canonical ABI encodings of
  `execute(bytes32,bytes)` and `executeFromExecutor(bytes32,bytes)`. It separately recognizes a
  canonical `uninstallModule(uint256,address,bytes)` call that removes this hook. Non-canonical,
  short, trailing, and unknown callback calldata reverts before execution decoding.
- **P3 — Honest `isModuleType`.** Module detection (`INV-04`) assumes targets implement
  `isModuleType` truthfully and return a canonical 32-byte ABI boolean. Adversarial bytecode that
  reverts, lies, or uses the same selector for another function is out of scope — see SG-B.

## Invariants

### INV-01 — The documented token-transfer selectors revert unless allowlisted
A non-allowlisted call carrying one of the following 10 selectors reverts
`TokenTransferNotAllowed(target, selector)`:

| Selector | Function |
| --- | --- |
| `0xa9059cbb` | `transfer(address,uint256)` |
| `0x095ea7b3` | `approve(address,uint256)` |
| `0x23b872dd` | `transferFrom(address,address,uint256)` |
| `0x39509351` | `increaseAllowance(address,uint256)` |
| `0xa457c2d7` | `decreaseAllowance(address,uint256)` |
| `0x42842e0e` | `safeTransferFrom(address,address,uint256)` |
| `0xb88d4fde` | `safeTransferFrom(address,address,uint256,bytes)` |
| `0xa22cb465` | `setApprovalForAll(address,bool)` |
| `0xf242432a` | `safeTransferFrom(address,address,uint256,uint256,bytes)` |
| `0x2eb2c2d6` | `safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)` |

This is a selector denylist, not a guarantee that all token-transfer mechanisms are blocked.
- **Severity:** Critical
- **Source:** `_checkCall`, `_isBlockedSelector` / FV `DSH-ALLOW-01`
- **Form:** observable outcome (exact iff over symbolic `bytes4`; oracle = 10 spec hex literals enumerated independently of `_isBlockedSelector`)
- **Preconditions / trusted assumptions:** P1, P2
- **Out of FV scope?:** no — **double-proven, TCB-independent** (Halmos + Certora; shared residual solc 0.8.30 via_ir)

### INV-02 — Delegatecall execution always reverts
Any execution whose call type is `CALLTYPE_DELEGATECALL` reverts `DelegateCallNotAllowed` in `preCheck`.
- **Severity:** High
- **Source:** `_checkExecutionCallback`
- **Form:** observable outcome
- **Preconditions / trusted assumptions:** P1, P2
- **Out of FV scope?:** no

### INV-03 — Self-call and zero-target aliases always revert
Any call whose target is the account reverts `SelfCallNotAllowed`, even if the account or
selector was explicitly allowlisted. A raw `address(0)` target is normalized to the account
before the self-call check, matching hosts that execute a zero target as a self-call.
- **Severity:** High
- **Source:** `_checkCall` / FV `check_DenyAllowlistedSelfCall`
- **Form:** observable outcome
- **Preconditions / trusted assumptions:** P1, P2
- **Out of FV scope?:** no

### INV-04 — Module calls revert except for authenticated Timelock creation
Any call to a target whose `isModuleType` staticcall succeeds with a canonical boolean result reverts
`ModuleCallNotAllowed(target)`, even if the module or selector was allowlisted, unless all of the
following hold: the call is the exact `createProposal(bytes32,bytes,uint256)` selector, that selector
was explicitly allowlisted for the target, the value is zero, and the target returns its authorization
magic for a live transient commitment bound to the account and current EntryPoint UserOperation.
Wildcard target allowlisting does not enable the exception.
- **Severity:** High
- **Source:** `_checkCall`, `_isModule` / FV `check_DenyAllowlistedModuleCall`
- **Form:** observable outcome (conditional deny branch only)
- **Preconditions / trusted assumptions:** P1, P2, **P3** (heuristic soundness is SG-B, NOT covered by this proof)
- **Out of FV scope?:** no (branch); soundness of the heuristic itself → SG-B (out of scope)

### INV-05 — ETH transfer to non-allowlisted target reverts
A non-allowlisted, non-self, non-module call with `value > 0` reverts `ETHTransferNotAllowed(target, value)`.
- **Severity:** Medium
- **Source:** `_checkCall` / FV `DSH-DENY-ETH-01::symbolic-target`
- **Form:** observable outcome
- **Preconditions / trusted assumptions:** P1, P2
- **Out of FV scope?:** no — proven (symbolic target concretizes to deployed code; codeless targets excluded by the contract itself)

### INV-06 — Allowlisted ordinary targets bypass value and token-selector checks
If `(msg.sender, normalizedTarget)` is neither the account nor module-typed and is allowlisted,
then `allSelectorsAllowed` or a matching selector lets `_checkCall` return without applying the
ETH-value and token-selector restrictions. Allowlisting the account, `address(0)`, a policy,
signer, or other module cannot bypass INV-03 or INV-04. The authenticated Timelock exception in
INV-04 follows its own stricter checks and is not an ordinary allowlist bypass.
- **Severity:** High
- **Source:** `_checkCall`
- **Form:** observable outcome (converse of INV-01; proven allowlisted-never-reverts leg of DSH-ALLOW-01)
- **Preconditions / trusted assumptions:** P1, P2
- **Out of FV scope?:** no

### INV-07 — Install lifecycle: double-install reverts; management gated on init
`onInstall` on an already-initialized account reverts `AlreadyInitialized`; `setAllowlist` /
`removeAllowlist` revert `Unauthorized` when the caller is not initialized.
- **Severity:** High
- **Source:** `onInstall`, `setAllowlist`, `removeAllowlist` / FV legs (a) `DSH-INSTALL-DOUBLE-01`, (b,c) `check_{Set,Remove}AllowlistRevertsWhenUninitialized`
- **Form:** observable outcome
- **Preconditions / trusted assumptions:** none
- **Out of FV scope?:** no — proven (leg a double-install; legs b,c management-gating)
- **Leg (d) — `onUninstall` NotInitialized guard**: the symmetric guard that `onUninstall`
  on a non-initialized account reverts `NotInitialized`. **Severity Low; Out of FV scope = yes (accepted,
  not proven, taek 2026-07-14).** Below the bar where a proof earns its keep — caller is the account,
  a broken guard deletes already-empty state (no attacker gain). Trivially provable from the
  double-install template if ever wanted. See report SG-G.

### INV-08 — Uninstall clears all state through a unique active-target set
After `onUninstall`, no target remains allowlisted for the account, and no previously-allowed
selector survives to be honored after a later re-install (S-01 stale-selector + S-03 target-cleanup fix).
The tracked target set contains each active target once and removes it with swap-and-pop, so repeated
remove/re-add cycles cannot accumulate duplicate cleanup entries.
- **Severity:** High
- **Source:** `onUninstall`, `_setAllowlist`, `_clearAllowlist` / FV `DSH-REMOVE-ALLOWLIST-01` / Certora S01/S02/S03
- **Form:** observable outcome (removal restores deny; re-set clears stale selectors)
- **Preconditions / trusted assumptions:** none
- **Out of FV scope?:** no

### INV-09 — Batch: every element is checked through the real decoder
In a `CALLTYPE_BATCH` execution, `_checkCall` runs on every decoded element; the batch reverts if
any element would revert on the single path — the real `decodeBatch`/`getExecution` calldata decode
introduces no bypass.
- **Severity:** Medium
- **Source:** `_checkExecutionCallback` / FV `DSH-BATCH-DECODER-01`
- **Form:** observable outcome (iff proven in both directions through the real decoder; closes the
  prior Certora `Call[]`-struct-model caveat — decode path now inside the proof, not the TCB)
- **Preconditions / trusted assumptions:** P1, P2
- **Out of FV scope?:** no — proven (coverage bound: batch length concrete at 2, element values/selectors symbolic)

### INV-10 — Callback dispatch cannot misdecode lifecycle or fallback calldata
`preCheck` dispatches on the outer account function selector and validates the complete canonical ABI
shape before reading execution data. Canonical calls to remove this hook pass without execution
decoding. Module installation, removal of other modules, unknown account callbacks, and malformed
supported callbacks revert.
- **Severity:** High
- **Source:** `preCheck`, `_decodeExecutionCallback`, `_decodeModuleCallback`, `_validateDynamicCallback`
- **Form:** observable outcome
- **Preconditions / trusted assumptions:** P1, P2
- **Out of FV scope?:** yes — covered by targeted regression tests; the formal suite must be extended
  before treating this callback-dispatch claim as formally proven.

## Out-of-FV-scope (recorded, accepted — not proof gaps)

Naming these is the honest analog of "to be end-to-end you'd have to verify everything." Each was
explicitly accepted by taek on 2026-07-14; none is a covering-claim failure.

- **SG-A (Medium) — denylist is non-exhaustive.** Only the 10 functions listed in INV-01 are
  recognized. ERC-777 `send`, ERC-1363 `transferAndCall` (`0x4000aea0`), EIP-3009
  `transferWithAuthorization` (`0xe3ee160e`), permit-based pulls, custom token extensions, and any
  other unlisted selector can pass when the target, value, and other checks pass. Users must not rely
  on this hook to prevent every token transfer. Revisit the threat model and formal oracle whenever
  the selector set changes.
- **SG-B (Medium) — `_isModule` heuristic soundness.** A target whose `isModuleType` reverts,
  returns a noncanonical value, or lies bypasses the module gate. EOAs and contracts that return no
  data are correctly treated as non-modules. Selector collisions that return a canonical boolean can
  cause a false positive. This depends on arbitrary external bytecode and is not FV-decidable.
  **Accepted; routed to sc-invariant-fuzz-tester** with adversarial target mocks. INV-04 proves only
  the conditional deny branch, not the heuristic.
- **SG-C — flows the hook never sees.** ERC-2612/Permit2/ERC-1271 signature approvals, pre-existing
  token approvals, and inbound `receive()` ETH are outside execution-call inspection. Unknown host
  fallback callbacks are rejected, while canonical `executeFromExecutor` callbacks receive the same
  call checks as `execute`. No hook-level covering claim is possible for flows the host does not send
  through `preCheck`.
- **SG-D (Medium) — Timelock authorizer trust.** The authenticated module exception trusts an
  explicitly configured target to implement `isProposalCreationAuthorized` honestly. A malicious or
  upgraded target can return the magic value for its exact `createProposal` selector. The account must
  trust and pin that target. The query is capped at 150,000 gas; an error, malformed return, or
  over-budget response fails closed.

## Permission-isolation deployment boundary

INV-03, INV-04, and INV-10 prevent a restricted permission protected by this hook from calling
Kernel module management or directly invoking policy checks and signer lifecycle callbacks. The
one module-call exception permits only a live, exact Timelock proposal creation after explicit
selector configuration. This mitigates
TOB-KERNEL-15, TOB-KERNEL-21, and TOB-KERNEL-22 for that permission even if an account/module target
or sensitive selector was mistakenly allowlisted.

This is a deployment boundary rather than host-wide callback authentication. Every restricted
permission must use this hook, the host must enforce it as described by P1, and no executor or
alternate unfiltered route may make the same account calls. Permissions without this hook remain
exposed to the Kernel-level callback-context findings.

## Recovery configuration incompatibility

`RecoveryAction` must run by delegatecall so validator lifecycle calls observe the account as
`msg.sender`. INV-02 rejects that call type before target/selector allowlist checks, so allowlisting
`RecoveryAction` cannot make it compatible with an execution path protected by this hook. Deployments
must provide and test an independent account-authorized recovery route before relying on recovery.
