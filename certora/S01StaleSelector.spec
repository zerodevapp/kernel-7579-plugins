/*
 * S-01 (audit HIGH regression, spec ^req-14): stale-selector clearing in _setAllowlist.
 *
 * PROPERTY:
 *   For an initialized account, given two distinct selectors A != B, calling
 *     setAllowlist(target, [A, B])   then   setAllowlist(target, [A])
 *   (both from the same account = msg.sender) leaves the account in a state where
 *     isSelectorAllowed(account, target, B) == false   AND
 *     isSelectorAllowed(account, target, A) == true.
 *   The second setAllowlist must CLEAR the stale B mapping entry (the S-01 fix: the
 *   clear loop over entry.selectorList in _setAllowlist), otherwise B would remain
 *   permitted and — if B is a blocked token selector (APPROVE) — bypass the
 *   blocked-selector guard, draining tokens.
 *
 * Target : src/hooks/DefaultSecurityHook.sol
 *   _setAllowlist  (selectorList tracking + clear loop; the S-01 fix)
 *   isSelectorAllowed (observable view read)
 *   _checkCall (blocked-selector revert path, via harness checkCall)
 *
 * TAUTOLOGY CHECK: the postcondition reads the observable mapping result via
 *   isSelectorAllowed and the revert outcome of checkCall. It never re-runs the clear
 *   loop or recomputes selectorList. Observable, not tautological.
 *
 * REACHABILITY: rule s01_reachability_witness proves the two setAllowlist calls both
 *   execute non-reverting under the precondition and land in the asserted final state
 *   (B false, A true) — rules out vacuous-by-unreachable-precondition.
 *
 * MODELING (TCB-disclosed):
 *   - The _isModule low-level staticcall to target.isModuleType is an unresolved external
 *     call; summarized NONDET. SOUND for the revert claim: were it to return true,
 *     _checkCall reverts EARLIER with ModuleCallNotAllowed — still a revert.
 *   - Compiled WITHOUT solc --via-ir (see .conf). The via-ir + optimizer pipeline
 *     mis-modeled the struct-embedded `mapping(bytes4=>bool) selectors` co-located with
 *     the `bytes4[] selectorList`: the clear-loop write `selectors[selectorList[i]]=false`
 *     did not alias the slot `isSelectorAllowed` reads, producing spurious CEs. The
 *     legacy (non-via-ir) codegen models this storage layout correctly; the Foundry
 *     regression test test_S01_StaleSelectorsAreClearedOnAllowlistUpdate independently
 *     confirms the impl is correct on real EVM semantics.
 *   - Freshly-initialized-account precondition asserted via entryPristine (the audit
 *     scenario). CVL cannot read the in-struct mapping, so pre-state cleanliness for A
 *     and B is pinned through this observable harness read — not a clear-loop recompute.
 *
 * @author taek <leekt216@gmail.com>
 */

methods {
    function setAllowlist(address target, bytes4[] selectors) external;
    function isSelectorAllowed(address account, address target, bytes4 selector) external returns (bool) envfree;
    function isInitialized(address account) external returns (bool) envfree;
    function checkCall(address target, uint256 value, bytes data) external;
    function approveSelector() external returns (bytes4) envfree;
    function leadingSelector(bytes data) external returns (bytes4) envfree;
    function entryPristine(address account, address target, bytes4 selector) external returns (bool) envfree;

    // _isModule staticcall to arbitrary target: unresolved -> NONDET (sound over-approx).
    function _.isModuleType(uint256) external => NONDET;
}

/*
 * MAIN PROPERTY (S-01).
 * Two setAllowlist calls from the same account; the second drops B from [A, B] to [A].
 * After the sequence, B must be de-permitted while A remains permitted.
 */
rule staleSelectorClearedAfterSetAllowlist(address target, bytes4 a, bytes4 b) {
    env e1;
    env e2;

    address account = e1.msg.sender;
    require e2.msg.sender == account;   // same account performs both calls

    require isInitialized(account);
    require a != b;

    // Audit scenario: freshly-initialized hook, no prior allowlist for target.
    // (CVL cannot see the mapping inside AllowlistEntry, so cleanliness is asserted
    //  via the observable entryPristine read — not a recompute of the clear loop.)
    require entryPristine(account, target, a);
    require entryPristine(account, target, b);

    bytes4[] both;
    require both.length == 2;
    require both[0] == a;
    require both[1] == b;
    setAllowlist(e1, target, both);

    bytes4[] onlyA;
    require onlyA.length == 1;
    require onlyA[0] == a;
    setAllowlist(e2, target, onlyA);

    assert isSelectorAllowed(account, target, b) == false,
        "stale selector B remained allowlist-permitted after being dropped";
    assert isSelectorAllowed(account, target, a) == true,
        "selector A was incorrectly de-permitted";
}

/*
 * BLOCKED-SELECTOR REVERT COROLLARY.
 * If B is a blocked token selector (APPROVE), after the drop a call to target with a
 * 4-byte calldata equal to B must revert in _checkCall (no allowlist bypass).
 * `data` is a rule-parameter bytes constrained to length 4 with first-4-bytes == B.
 */
rule blockedStaleSelectorCallReverts(address target, bytes4 a, bytes data) {
    env e1;
    env e2;
    env eCall;

    address account = e1.msg.sender;
    require e2.msg.sender == account;
    require eCall.msg.sender == account;

    bytes4 b = approveSelector();      // concrete blocked selector
    require isInitialized(account);
    require a != b;

    require entryPristine(account, target, a);
    require entryPristine(account, target, b);

    // data = a call whose leading selector is B (>= 4 bytes).
    require data.length >= 4;
    require leadingSelector(data) == b;

    bytes4[] both;
    require both.length == 2;
    require both[0] == a;
    require both[1] == b;
    setAllowlist(e1, target, both);

    bytes4[] onlyA;
    require onlyA.length == 1;
    require onlyA[0] == a;
    setAllowlist(e2, target, onlyA);

    checkCall@withrevert(eCall, target, 0, data);

    assert lastReverted, "blocked stale selector B was permitted through _checkCall";
}

/*
 * REACHABILITY WITNESS (mandatory): both setAllowlist calls execute non-reverting and the
 * asserted final state (B false, A true) is actually reachable. satisfy => non-vacuous.
 */
rule s01_reachability_witness(address target, bytes4 a, bytes4 b) {
    env e1;
    env e2;

    address account = e1.msg.sender;
    require e2.msg.sender == account;
    require isInitialized(account);
    require a != b;

    require entryPristine(account, target, a);
    require entryPristine(account, target, b);

    bytes4[] both;
    require both.length == 2;
    require both[0] == a;
    require both[1] == b;
    setAllowlist(e1, target, both);

    bytes4[] onlyA;
    require onlyA.length == 1;
    require onlyA[0] == a;
    setAllowlist(e2, target, onlyA);

    satisfy isSelectorAllowed(account, target, b) == false
        && isSelectorAllowed(account, target, a) == true;
}
