/*
 * WECDSA-THRESHOLD-01 (RE-ANCHORED) — TOB-17 (no double-count) + TOB-16 (check-before-count
 * ordering) + threshold-soundness for the SIGNER's installed ERC-1271 path, AFTER the EC-01
 * refactor moved the aggregation logic onto the shared WeightedThresholdBase.
 *
 * The pre-refactor version of this spec summarized an in-signer `_validateSignature` that no
 * longer exists and the harness reimplemented the loop byte-for-byte. This version RE-ANCHORS the
 * same observable property onto the MOVED code: the harness (certora/harness/WeightedECDSASigner-
 * Harness.sol) derives from the real WeightedECDSASigner and drives the REAL, COMPILED base
 * bytecode WeightedThresholdBase._verifySorted (src/base/WeightedThresholdBase.sol:38-93) exactly
 * as reached through WeightedECDSASigner.checkSignature (:162-170) -> _verifySorted ->
 * _guardianWeight (id-keyed guardian[signer][cfg][account], :122-129). No hand copy of the loop
 * remains, so a behavioral drift introduced by the move would be caught here.
 *
 * OBSERVABLE PROPERTY (not a re-run of the summation loop):
 *   a duplicate signer (two slices recovering the same address) NEVER yields acceptance with that
 *   address's weight counted twice — the ascending gate `signer <= lastSigner` (base :61 / :79)
 *   fires on the equal second signer BEFORE its weight is added (base :71 / :87).
 *
 * ECDSA.tryRecoverCalldata is inline assembly the SMT engine cannot invert. It is summarized as an
 * UNINTERPRETED, DETERMINISTIC ghost `recoveredSigner(i)` keyed on the RECOVERY CALL INDEX i.
 * _verifySorted recovers slice 0 first (loop i=0) then the last slice in strict program order, so
 * call index == slice index for the small slice counts these rules use (1 and 2). Same slice ->
 * same call index -> same address. The proof covers ordering/threshold logic, NOT ECDSA soundness.
 * TCB: solc8.30 (via-IR) + Certora solver; recovery abstracted; keccak default-modelled.
 *
 * @author taek <leekt216@gmail.com>
 */

using WeightedECDSASignerHarness as h;

methods {
    // threshold()/weightOf() read guardian storage at (ID, msg.sender); env-bound so the account
    // matches the msg.sender validateSignature drives _verifySorted with (same e passed to all three).
    function threshold() external returns (uint24);
    function weightOf(address) external returns (uint24);
    // Recovery: summarized by monotonically increasing CALL INDEX -> recoveredSigner(index).
    function _.tryRecoverCalldata(bytes32 hash, bytes calldata sigSlice) internal => recoverByIndex() expect address;
}

// Uninterpreted, deterministic per-index recovery. Same call index -> same address.
ghost recoveredSigner(mathint) returns address;

// Per-execution recovery-call counter (reset to 0 at the start of each rule).
ghost mathint recoverCallCount {
    init_state axiom recoverCallCount == 0;
}

// Summary body: return recoveredSigner(current count), then advance the counter. slice 0 is the
// first recover call (loop i=0), the last slice the second, matching recoveredSigner(0/1).
function recoverByIndex() returns address {
    address r = recoveredSigner(recoverCallCount);
    recoverCallCount = recoverCallCount + 1;
    return r;
}

definition MAGIC()   returns bytes4 = to_bytes4(0x1626ba7e);
definition INVALID() returns bytes4 = to_bytes4(0xffffffff);

// sig length for a given slice count (65 bytes/slice).
definition SIG2() returns mathint = 130;
definition SIG1() returns mathint = 65;

/*
 * MAIN PROPERTY (TOB-17 double-count, contrapositive) — the dispatched claim, RE-ANCHORED.
 * For a two-slice input where the two recovered signers are IDENTICAL (a duplicate) and a SINGLE
 * copy of that signer's weight is below threshold, the REAL base _verifySorted can NEVER accept.
 *
 * Under the ascending gate with sentinel 0: loop iteration i=0 processes slice 0 (adds w once,
 * w<threshold so no early accept), then the last-slice pass processes slice 1 and the guard
 * `signer <= lastSigner` (s1 == s0 <= s0) fires FIRST and returns false before lastWeight is added.
 * Observable: the RETURN value under a duplicate-signer precondition; it does NOT recompute recover
 * or re-sum the running total.
 */
rule duplicateSignerNeverAccepts() {
    env e;
    require recoverCallCount == 0;
    bytes sigData;
    require sigData.length == assert_uint256(SIG2());               // exactly two 65-byte slices

    address s0 = recoveredSigner(0);
    address s1 = recoveredSigner(1);

    require s0 != 0;                                                // exclude the sentinel corner
    require s0 == s1;                                               // duplicate slice -> same signer
    require weightOf(e, s0) > 0;                                    // s0 is a real guardian
    require to_mathint(threshold(e)) > to_mathint(weightOf(e, s0)); // one copy alone is insufficient

    bytes4 ret = h.validateSignature(e, sigData);

    assert ret != MAGIC(),
        "duplicate signer reached threshold via double-counting -- ascending gate failed";
}

/*
 * COMPLEMENT / scoping: a single guardian whose weight already meets threshold IS accepted (via the
 * real base). Proves the main rule is scoped to the double-counting bug, not over-claiming that
 * duplicates always reject. With sigCount==1 the loop body (0 .. sigCount-2) is skipped; the
 * last-slice pass processes slice 0: guard `s0 <= 0` is false (s0 != 0), weight added, threshold met.
 */
rule singleSufficientSignerAccepts() {
    env e;
    require recoverCallCount == 0;
    bytes sigData;
    require sigData.length == assert_uint256(SIG1());               // exactly one slice

    address s0 = recoveredSigner(0);

    require s0 != 0;                                                // sentinel corner excluded
    require to_mathint(weightOf(e, s0)) >= to_mathint(threshold(e));
    require threshold(e) != 0;

    bytes4 ret = h.validateSignature(e, sigData);

    assert ret == MAGIC(),
        "a single guardian whose weight meets threshold must be accepted";
}

/*
 * REACHABILITY WITNESS (i) — MANDATORY non-vacuous ACCEPT via TWO DISTINCT signers over the REAL
 * base. There EXISTS a two-slice input with distinct, strictly-ascending signers whose combined
 * weight reaches threshold and returns MAGICVALUE. Kills vacuity of the accept path.
 */
rule witnessTwoDistinctAccept() {
    env e;
    require recoverCallCount == 0;
    bytes sigData;
    require sigData.length == assert_uint256(SIG2());

    address s0 = recoveredSigner(0);
    address s1 = recoveredSigner(1);

    require s0 != 0;                                                                              // sentinel excluded
    require s0 < s1;                                                                              // strictly ascending -> distinct
    require to_mathint(weightOf(e, s0)) < to_mathint(threshold(e));                               // first alone insufficient
    require to_mathint(weightOf(e, s0)) + to_mathint(weightOf(e, s1)) >= to_mathint(threshold(e)); // together sufficient
    require threshold(e) != 0;

    bytes4 ret = h.validateSignature(e, sigData);

    satisfy ret == MAGIC(),
        "no reachable accept from two distinct guardians summing to threshold";
}

/*
 * REACHABILITY WITNESS (ii) — the TOB-17 PoC is reachable AND discriminated over the REAL base.
 * There EXISTS a duplicate (s0==s1) with 2w>=threshold>w that returns INVALID: the exact pre-fix
 * exploit input, now correctly rejected by the check-before-count gate.
 */
rule witnessDuplicatePoCRejected() {
    env e;
    require recoverCallCount == 0;
    bytes sigData;
    require sigData.length == assert_uint256(SIG2());

    address s0 = recoveredSigner(0);
    address s1 = recoveredSigner(1);

    require s0 != 0;
    require s0 == s1;
    uint24 w = weightOf(e, s0);
    require w > 0;
    require 2 * to_mathint(w) >= to_mathint(threshold(e));       // WOULD reach threshold if double-counted
    require to_mathint(threshold(e)) > to_mathint(w);            // one copy alone does NOT

    bytes4 ret = h.validateSignature(e, sigData);

    satisfy ret == INVALID(),
        "TOB-17 PoC (duplicate, 2w>=threshold>w) not reachable as a rejection";
}
