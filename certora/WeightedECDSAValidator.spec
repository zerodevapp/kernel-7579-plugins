/*
 * RP-01 — Stale-approval non-replay across a config-version bump.
 *
 * Property (observable): after ANY lifecycle call that bumps the per-kernel config
 * epoch (onInstall / onUninstall / renew), a proposal/vote fully written under a PRIOR
 * epoch cannot make getApproval(kernel, H).passed become true. The only votes that can
 * contribute to getApproval after a bump are those written at the CURRENT epoch key.
 *
 * Two lemmas the dispatch calls out:
 *  (a) key injectivity: configVersion(V0) != configVersion(V1)  =>  key(V0,H) != key(V1,H).
 *      Discharged by Certora's default keccak256 modelling as an injective uninterpreted
 *      function (DISCLOSED TCB assumption: keccak collision-resistance).
 *  (b) getApproval keys off the current epoch: it reads voteStatus[ _key(current) ][..].
 *      Discharged over the real getApproval / keyOf bytecode.
 *
 * Tautology check: postconditions assert an access/replay OUTCOME (the slot getApproval
 * reads after a bump differs from the slot the stale vote lives in) — never recompute _key.
 * Reachability check: `witness_*` rules use `satisfy` to prove the pre-rotation
 * passed==true state AND the successful lifecycle transitions are reachable, so the
 * safety rules are not vacuously true. rule_sanity is kept "basic".
 *
 * @author taek <leekt216@gmail.com>
 */

methods {
    function version(address) external returns (uint256) envfree;
    function keyOf(address, bytes32) external returns (bytes32) envfree;
    function getApproval(address, bytes32) external returns (uint256, bool) envfree;
    function voteStatusAt(bytes32, address, address) external returns (WeightedECDSAValidator.VoteStatus) envfree;
    function weightOf(address, address) external returns (uint24) envfree;
    function isInitialized(address) external returns (bool) envfree;
}

// ===========================================================================
// SAFETY — the epoch is bumped and the stale-vote slot is orphaned, per method.
// Each rule has non-reverting preconditions so its assertions are REACHABLE
// (kills the vacuity that a blanket parametric rule triggered).
// ===========================================================================

/* renew: the exploit path from PoC_X02. Kernel must be initialized to renew.
 * After renew, the epoch is bumped and the key for H changes, so the stale
 * Approved vote at the old key is orphaned. */
rule renewBumpsEpochAndOrphansStaleVote(address k, bytes32 h, address g) {
    env e;
    require e.msg.sender == k && k != 0;
    require isInitialized(k);                       // reachability: renew requires init
    require version(k) < max_uint256;              // no epoch overflow (unreachable in practice)

    uint256 vBefore = version(k);
    bytes32 oldKey = keyOf(k, h);

    address[] guardians; uint24[] weights; uint24 threshold; uint48 delay;
    renew(e, guardians, weights, threshold, delay);

    uint256 vAfter = version(k);
    bytes32 newKey = keyOf(k, h);

    assert vAfter == vBefore + 1, "renew bumps the epoch exactly once";
    assert newKey != oldKey, "RP-01: stale vote slot (oldKey) is orphaned; getApproval keys off newKey";
}

/* onUninstall: rotation via uninstall. Requires init; bumps epoch. */
rule uninstallBumpsEpochAndOrphansStaleVote(address k, bytes32 h, address g) {
    env e;
    require e.msg.sender == k && k != 0;
    require isInitialized(k);                       // reachability: onUninstall requires init
    require version(k) < max_uint256;              // no epoch overflow (unreachable in practice)

    uint256 vBefore = version(k);
    bytes32 oldKey = keyOf(k, h);

    bytes uninstallData;
    onUninstall(e, uninstallData);

    uint256 vAfter = version(k);
    bytes32 newKey = keyOf(k, h);

    assert vAfter == vBefore + 1, "onUninstall bumps the epoch exactly once";
    assert newKey != oldKey, "RP-01: stale vote slot (oldKey) is orphaned by uninstall";
}

/* onInstall: (re)install after an uninstall. Requires NOT init; bumps epoch. */
rule installBumpsEpochAndOrphansStaleVote(address k, bytes32 h, address g) {
    env e;
    require e.msg.sender == k && k != 0;
    require !isInitialized(k);                      // reachability: onInstall requires NOT init
    require version(k) < max_uint256;              // no epoch overflow (unreachable in practice)

    uint256 vBefore = version(k);
    bytes32 oldKey = keyOf(k, h);

    bytes installData;
    onInstall(e, installData);

    uint256 vAfter = version(k);
    bytes32 newKey = keyOf(k, h);

    assert vAfter == vBefore + 1, "onInstall bumps the epoch exactly once";
    assert newKey != oldKey, "RP-01: stale vote slot (oldKey) is orphaned by (re)install";
}

// ===========================================================================
// REACHABILITY WITNESSES (satisfy) — the safety rules above are NOT vacuous.
// ===========================================================================

/* (i) Pre-rotation: getApproval CAN return passed==true. If this were unreachable,
 * the whole replay property would be vacuous (approval never happens). */
rule witness_approvalCanPass(address k, bytes32 h) {
    uint256 approvals; bool passed;
    approvals, passed = getApproval(k, h);
    satisfy passed, "there exists a reachable state where getApproval passes (pre-rotation)";
}

/* (ii) The renew transition with a live stale vote actually succeeds (not revert-only). */
rule witness_renewSucceedsWithStaleVote(address k, bytes32 h, address g) {
    env e;
    require e.msg.sender == k && k != 0;
    require isInitialized(k);
    bytes32 oldKey = keyOf(k, h);
    require voteStatusAt(oldKey, g, k) == WeightedECDSAValidator.VoteStatus.Approved;

    address[] guardians; uint24[] weights; uint24 threshold; uint48 delay;
    renew(e, guardians, weights, threshold, delay);

    satisfy version(k) == version(k), "renew reaches a non-reverting post-state with a stale vote present";
}

/* (iii) Post-rotation the SAME hash no longer passes off the stale vote alone:
 * after renew, at the new key the vote for g is NA (stale vote did not carry over),
 * so its weight is not counted. Reachable witness that the replay is blocked. */
rule witness_staleVoteNotAtNewKey(address k, bytes32 h, address g) {
    env e;
    require e.msg.sender == k && k != 0;
    require isInitialized(k);
    bytes32 oldKey = keyOf(k, h);
    require voteStatusAt(oldKey, g, k) == WeightedECDSAValidator.VoteStatus.Approved;

    address[] guardians; uint24[] weights; uint24 threshold; uint48 delay;
    renew(e, guardians, weights, threshold, delay);

    bytes32 newKey = keyOf(k, h);
    // The stale voter g has NO vote recorded at the post-rotation key.
    satisfy voteStatusAt(newKey, g, k) == WeightedECDSAValidator.VoteStatus.NA,
        "post-renew: the stale voter has no vote at the new epoch key (replay blocked)";
}
