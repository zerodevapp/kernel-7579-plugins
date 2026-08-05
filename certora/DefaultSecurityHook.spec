/*
 * DSH-ALLOW-01 — Allowlist gating is exact for blocked token selectors.
 *
 * Target: DefaultSecurityHook._checkCall (exposed via harness `checkCall`).
 *
 * OBSERVABLE property (not a recompute of _isBlockedSelector):
 *   Given `sel` (the leading-4-byte selector of `data`, exactly as _checkCall reads
 *   it) already CONSTRAINED to be one of the 10 blocked selectors — an INPUT
 *   constraint, NOT a postcondition re-derivation — and given a non-self / non-module
 *   / zero-value target:
 *     - if NOT ( allowed && (allSelectorsAllowed || selectorMapped) ) then checkCall
 *       MUST revert. Self / module / ETH branches are excluded by the preconditions,
 *       so the only reachable revert is TokenTransferNotAllowed.
 *   Conversely:
 *     - if allSelectorsAllowed for the target, checkCall MUST NOT revert regardless of
 *       selector or value.
 *
 * The allowlist facts are read via observable harness accessors
 * (h_allowed / h_allSelectorsAllowed / h_selectorMapped) — state reads, not a
 * reimplementation of blocked-set membership. `sel` comes from selOf (a calldata
 * slice), the SAME key _checkCall uses for the mapping lookup.
 */

methods {
    function checkCall(address, uint256, bytes) external; // NOT envfree: reads msg.sender (the account)
    function selOf(bytes) external returns (bytes4) envfree; // bytes4(data[:4]) as _checkCall reads it
    function h_allowed(address, address) external returns (bool) envfree;
    function h_allSelectorsAllowed(address, address) external returns (bool) envfree;
    function h_selectorMapped(address, address, bytes4) external returns (bool) envfree;

    // _isModule(target) does a raw staticcall probe to `target`. We summarize the
    // internal function directly to `false`, pinning the STATEMENT's "non-module"
    // precondition: the module-revert branch is never taken, so a non-allowlisted
    // blocked selector must flow to the TokenTransferNotAllowed branch.
    // (The converse rule returns via the allowlist branch before _isModule is reached,
    //  so this summary does not affect it.)
    function DefaultSecurityHook._isModule(address) internal returns (bool) => notAModule();
}

// Non-module summary for _isModule (see methods note).
function notAModule() returns bool {
    return false;
}

// The 10 blocked selectors (input-constraint constants; see tautology note above).
definition BLOCKED(bytes4 s) returns bool =
       s == to_bytes4(0xa9059cbb)  // transfer(address,uint256)
    || s == to_bytes4(0x095ea7b3)  // approve(address,uint256)
    || s == to_bytes4(0x23b872dd)  // transferFrom(address,address,uint256)
    || s == to_bytes4(0x39509351)  // increaseAllowance(address,uint256)
    || s == to_bytes4(0xa457c2d7)  // decreaseAllowance(address,uint256)
    || s == to_bytes4(0x42842e0e)  // safeTransferFrom(address,address,uint256)
    || s == to_bytes4(0xb88d4fde)  // safeTransferFrom(address,address,uint256,bytes)
    || s == to_bytes4(0xa22cb465)  // setApprovalForAll(address,bool)
    || s == to_bytes4(0xf242432a)  // safeTransferFrom(address,address,uint256,uint256,bytes)
    || s == to_bytes4(0x2eb2c2d6); // safeBatchTransferFrom(...)

// Observable "allowlisted pass" predicate over harness state reads.
definition ALLOW_PASS(address acct, address target, bytes4 sel) returns bool =
    h_allowed(acct, target) && ( h_allSelectorsAllowed(acct, target) || h_selectorMapped(acct, target, sel) );

// ---------------------------------------------------------------------------
// MAIN RULE: deny direction (security-critical).
// A blocked selector to a non-self, non-module, zero-value target that is NOT
// allowlist-passing MUST revert.
// ---------------------------------------------------------------------------
rule blockedSelectorDenyReverts(address target, bytes data) {
    env e;
    require e.msg.value == 0;
    address account = e.msg.sender; // account == msg.sender inside _checkCall

    require data.length == 4;       // full selector determined, no trailing bytes
    bytes4 sel = selOf(data);       // == bytes4(data[:4]) as _checkCall reads it

    // INPUT constraint: selector is a blocked one (not a postcondition re-derivation).
    require BLOCKED(sel);

    // Preconditions from the STATEMENT: non-self (target!=account), non-module
    // (_isModule summarized false), zero value (value==0 arg below).
    require target != account;
    require !ALLOW_PASS(account, target, sel);

    checkCall@withrevert(e, target, /*value*/ 0, data);

    // With self / module / ETH branches excluded, the ONLY reachable revert is
    // TokenTransferNotAllowed. Assert it reverts.
    assert lastReverted, "Blocked, non-allowlisted, non-module, zero-value call did not revert";
}

// ---------------------------------------------------------------------------
// CONVERSE RULE: allSelectorsAllowed => never reverts regardless of selector/value.
// ---------------------------------------------------------------------------
rule allSelectorsAllowedNeverReverts(address target, uint256 value, bytes data) {
    env e;
    require e.msg.value == 0;
    address account = e.msg.sender;

    require h_allowed(account, target);
    require h_allSelectorsAllowed(account, target);

    checkCall@withrevert(e, target, value, data);

    assert !lastReverted, "allSelectorsAllowed target reverted";
}

// ---------------------------------------------------------------------------
// REACHABILITY WITNESS 1 (mandatory): deny branch is reachable.
// ---------------------------------------------------------------------------
rule witnessBlockedReverts(address target, bytes data) {
    env e;
    require e.msg.value == 0;
    address account = e.msg.sender;

    require data.length == 4;
    bytes4 sel = selOf(data);
    require BLOCKED(sel);
    require target != account;
    require !ALLOW_PASS(account, target, sel);

    checkCall@withrevert(e, target, 0, data);
    satisfy lastReverted, "no model where a blocked non-allowlisted call reverts";
}

// ---------------------------------------------------------------------------
// REACHABILITY WITNESS 2 (mandatory): pass branch is reachable.
// ---------------------------------------------------------------------------
rule witnessAllowlistedPasses(address target, bytes data) {
    env e;
    require e.msg.value == 0;
    address account = e.msg.sender;

    require h_allowed(account, target);
    require h_allSelectorsAllowed(account, target);

    checkCall@withrevert(e, target, 0, data);
    satisfy !lastReverted, "no model where an allSelectorsAllowed call passes";
}
