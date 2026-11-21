/*
 * EC-01 (audit High): isValidSignatureWithSender returns ERC1271_MAGICVALUE only when the
 * summed weight of DISTINCT guardians reaches threshold. A duplicated single-guardian
 * signature must NOT reach threshold.
 *
 * Target: src/validators/WeightedECDSAValidator.sol:294-320
 * Fix under test: the strictly-descending guard
 *   `if (signer >= prevSigner) return ERC1271_INVALID;`  (line 310)
 * runs BEFORE weight accumulation (line 314) + threshold return (line 315/316).
 *
 * ECDSA.recover is modeled UNINTERPRETED: recoveredSigner(i) is a symbolic,
 * attacker-controlled address, DETERMINISTIC in the loop index i (same 65-byte slice
 * data[i*65:(i+1)*65] -> same recovered address). The proof covers the aggregation/ordering
 * logic, NOT ECDSA soundness.
 *
 * @author taek <leekt216@gmail.com>
 */

methods {
    function threshold() external returns (uint24) envfree;
    function weightOf(address) external returns (uint24) envfree;
    function isValidSignatureWithSender(uint256) external returns (bytes4) envfree;
    function _recoverSigner(uint256 i) internal returns (address) => recoveredSigner(i);
}

// Uninterpreted, deterministic per-index recovery. Same i -> same address.
ghost recoveredSigner(uint256) returns address;

definition MAGIC()   returns bytes4 = to_bytes4(0x1626ba7e);
definition INVALID() returns bytes4 = to_bytes4(0xffffffff);

/*
 * MAIN PROPERTY (the exact audit bug class, contrapositive).
 * For a two-slice input where the two recovered signers are IDENTICAL (a duplicate) and a
 * SINGLE copy of that signer's weight is below threshold, the function can NEVER accept.
 *
 * Pre-fix, iteration-0 added w (w<threshold), iteration-1 saw the SAME address, and because
 * the ordering guard ran AFTER accumulation, it added w a second time -> 2w>=threshold ->
 * MAGICVALUE. Post-fix, iteration-1's guard `signer >= prevSigner` (s == s) fires FIRST and
 * returns INVALID before any second contribution.
 *
 * Observable: the RETURN value under a duplicate-signer precondition. It does NOT recompute
 * recover or the running total; the claim is that a duplicate cannot double-count -> not a
 * tautology (advanced sanity confirms the antecedent is reachable and the conclusion is
 * non-trivial via the witness rules below).
 */
rule duplicateSignerNeverAccepts() {
    address s0 = recoveredSigner(0);
    address s1 = recoveredSigner(1);

    require to_mathint(s0) < 2^160 - 1;                  // exclude the sentinel corner
    require s0 == s1;                                     // duplicate: same 65-byte slice recovers same signer
    require weightOf(s0) > 0;                             // s0 is a real guardian (loop genuinely counts)
    require to_mathint(threshold()) > to_mathint(weightOf(s0)); // one copy alone is insufficient

    bytes4 ret = isValidSignatureWithSender(2);

    assert ret != MAGIC(),
        "duplicate signer reached threshold via double-counting -- line-310 guard failed";
}

/*
 * COMPLEMENT: a duplicate whose SINGLE copy already meets threshold IS accepted at
 * iteration-0 (before the guard is even relevant). This proves the rule above is scoped to
 * the genuine bug (double-counting) and not over-claiming that duplicates always reject.
 */
rule singleSufficientSignerAccepts() {
    address s0 = recoveredSigner(0);

    // A recovered signer equal to the uint160-max sentinel is rejected by the very first
    // ordering guard (prevSigner initializes to that sentinel); exclude that corner so the
    // rule speaks to the weight logic. Any real guardian address is < 2^160-1.
    require to_mathint(s0) < 2^160 - 1;
    require to_mathint(weightOf(s0)) >= to_mathint(threshold());
    require threshold() != 0;

    bytes4 ret = isValidSignatureWithSender(1);

    assert ret == MAGIC(),
        "a single guardian whose weight meets threshold must be accepted";
}

/*
 * REACHABILITY WITNESS (i) -- non-vacuous ACCEPT via TWO DISTINCT signers.
 * There EXISTS a two-slice input with distinct, strictly-descending signers whose combined
 * weight reaches threshold and returns MAGICVALUE. Kills vacuity of the accept path.
 */
rule witnessTwoDistinctAccept() {
    address s0 = recoveredSigner(0);
    address s1 = recoveredSigner(1);

    require to_mathint(s0) < 2^160 - 1;                      // exclude the sentinel corner
    require s0 > s1;                                          // strictly descending -> distinct
    require to_mathint(weightOf(s0)) < to_mathint(threshold());          // first alone insufficient
    require to_mathint(weightOf(s0)) + to_mathint(weightOf(s1)) >= to_mathint(threshold()); // together sufficient
    require threshold() != 0;

    bytes4 ret = isValidSignatureWithSender(2);

    satisfy ret == MAGIC(),
        "no reachable accept from two distinct guardians summing to threshold";
}

/*
 * REACHABILITY WITNESS (ii) -- the audit PoC is reachable AND discriminated.
 * There EXISTS a duplicate (s0==s1) with 2w>=threshold>w that returns INVALID: the exact
 * pre-fix exploit input, now correctly rejected.
 */
rule witnessDuplicatePoCRejected() {
    address s0 = recoveredSigner(0);
    address s1 = recoveredSigner(1);

    require s0 == s1;
    uint24 w = weightOf(s0);
    require w > 0;
    require 2 * to_mathint(w) >= to_mathint(threshold());   // WOULD reach threshold if double-counted
    require to_mathint(threshold()) > to_mathint(w);        // one copy alone does NOT

    bytes4 ret = isValidSignatureWithSender(2);

    satisfy ret == INVALID(),
        "audit PoC (duplicate, 2w>=threshold>w) not reachable as a rejection";
}
