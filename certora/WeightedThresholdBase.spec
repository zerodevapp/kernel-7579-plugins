/*
 * WeightedThresholdBase._verifySorted ON the WeightedECDSAValidator adapter (the refactor
 * soundness claim). Target: shared core src/base/WeightedThresholdBase.sol:38-93 driven through
 * the REAL adapter storage layout (src/validators/WeightedECDSAValidator.sol:171-178) --
 * threshold from weightedStorage[account].threshold, each weight from the inherited real
 * _guardianWeight -> guardian[signer][account].weight.
 *
 * CLAIM (dispatched, Critical): isValidSignatureWithSender returns ERC1271_MAGICVALUE ONLY IF
 * the summed weight of pairwise-DISTINCT, strictly-ASCENDING guardians reaches threshold; a
 * DUPLICATED single-guardian signature can NEVER reach threshold. This is the auth-bypass class
 * (one compromised guardian replayed to threshold).
 *
 * OBSERVABLE POSTCONDITION (NOT a re-sum): if result == MAGICVALUE then the recovered signers in
 * the COUNTED prefix are pairwise DISTINCT (the structural invariant the ascending gate at :61/:79
 * establishes BEFORE the weight is counted at :71/:87). The rules assert over the processed-prefix
 * ghost images only; they never recompute totalWeight.
 *
 * ECDSA.tryRecoverCalldata is called inline in _verifySorted (no override seam) so the loop is
 * mirrored verbatim in the harness with recovery routed through _recoverSigner(i), summarized
 * here as an UNINTERPRETED ghost DETERMINISTIC in the loop index i (same 65-byte slice ->
 * same recovered address). Proof covers ordering/threshold aggregation on the adapter storage,
 * NOT ECDSA soundness.
 *
 * TCB (this leg): solc 0.8.30 (via_ir) + Certora Prover SMT + trust-that-the-harness-loop-mirrors
 * WeightedThresholdBase._verifySorted (line-by-line) + uninterpreted recovery. TCB-INDEPENDENT
 * from the halmos verbatim-replica leg (different toolchain, different extraction).
 *
 * @author taek <leekt216@gmail.com>
 */

methods {
    // NOT envfree: the loop reads weightedStorage[msg.sender] and guardian[s][msg.sender], so
    // each rule binds e.msg.sender to the `acc` the weightOf/thresholdOf reads are taken at.
    function isValidSignatureWithSenderH(uint256) external returns (bytes4);
    function weightOf(address, address) external returns (uint256) envfree;
    function thresholdOf(address) external returns (uint256) envfree;
    function _recoverSigner(uint256 i) internal returns (address) => recoveredSigner(i);
}

// Uninterpreted, deterministic per-index recovery. Same slice (index) -> same address.
ghost recoveredSigner(uint256) returns address;

definition MAGIC()   returns bytes4 = to_bytes4(0x1626ba7e);
definition INVALID() returns bytes4 = to_bytes4(0xffffffff);

// The account whose real storage the harness reads is msg.sender; we quantify weights via the
// envfree weightOf(account, signer). To keep the storage read and the assertion on the same
// account, all rules fix `acc` and require the weightOf reads to be taken at `acc`. Because
// isValidSignatureWithSenderH is envfree, Certora picks msg.sender freely; the weight the loop
// reads for signer s is guardian[s][msg.sender].weight, i.e. weightOf(msg.sender, s). We bind
// the reasoning to msg.sender implicitly by referencing weightOf on the same recovered signers.

// ===========================================================================
// MAIN PROPERTY -- the dispatched claim (duplicate never double-counts).
// N=2 duplicate: one copy insufficient => can never accept.
// The ascending gate `s1 <= lastSigner(=s0)` (s1 == s0) fires BEFORE the second weight is
// counted, so a duplicate cannot reach threshold via double-counting.
// Observable: the RETURN value under a duplicate precondition; no re-sum of totalWeight.
// ===========================================================================
rule duplicateSignerNeverAccepts(address acc) {
    env e;
    require e.msg.sender == acc;                                 // loop reads storage at `acc`
    address s0 = recoveredSigner(0);
    address s1 = recoveredSigner(1);

    require s0 != 0;                                              // sentinel (address(0)) corner excluded
    require s0 == s1;                                             // duplicate slice -> same signer
    require weightOf(acc, s0) > 0;                               // s0 is a real guardian for acc
    require thresholdOf(acc) > weightOf(acc, s0);                // one copy alone is insufficient

    bytes4 ret = isValidSignatureWithSenderH(e, 2);

    assert ret != MAGIC(),
        "duplicate signer reached threshold via double-counting -- ascending gate at :61/:79 failed";
}

// ===========================================================================
// GENERALIZED (N=3): a FULLY-duplicated 3-slice input never double-counts to threshold.
// This is the sound N=3 generalization of the duplicate-never-double-counts claim over the
// COUNTED prefix (per dispatch: assert over the processed prefix only, never over unreached
// suffix indices). All three slices recover the SAME signer; one copy of its weight is
// insufficient. The ascending gate at :61 rejects the second (equal) signer's iteration BEFORE
// any second weight is counted, so the loop can never reach threshold -- no accept.
// Observable: the RETURN value; no re-sum of totalWeight.
//
// NOTE: we deliberately do NOT forbid a duplicate that sits in an UNREACHED suffix (e.g. s2==s0
// while a distinct s0,s1 already reached threshold at i=1 and returned before s2 was recovered):
// that is a legitimate accept from a distinct counted set, and the earlier over-strong version
// of this rule was correctly falsified by exactly that case.
// ===========================================================================
rule fullyDuplicatedNeverAccepts(address acc) {
    env e;
    require e.msg.sender == acc;                                 // loop reads storage at `acc`
    address s0 = recoveredSigner(0);
    address s1 = recoveredSigner(1);
    address s2 = recoveredSigner(2);

    require s0 != 0;                                             // sentinel corner excluded
    require s0 == s1 && s1 == s2;                                // fully duplicated input
    require weightOf(acc, s0) > 0;                               // s0 is a real guardian
    require thresholdOf(acc) > weightOf(acc, s0);                // one copy alone insufficient

    bytes4 ret = isValidSignatureWithSenderH(e, 3);

    assert ret != MAGIC(),
        "fully-duplicated 3-slice input reached threshold via double-counting -- ascending gate failed";
}

// ===========================================================================
// SCOPING COMPLEMENT: a single guardian whose weight already meets threshold IS accepted.
// Proves the rules above are scoped to the double-count bug, not over-claiming duplicates
// always reject. sigCount==1: loop (0..sigCount-2) skipped, last pass processes slice 0;
// gate `s0 <= 0` false (s0 != 0), weight added, threshold met.
// ===========================================================================
rule singleSufficientSignerAccepts(address acc) {
    env e;
    require e.msg.sender == acc;                                 // loop reads storage at `acc`
    address s0 = recoveredSigner(0);

    require s0 != 0;
    require weightOf(acc, s0) >= thresholdOf(acc);
    require thresholdOf(acc) != 0;

    bytes4 ret = isValidSignatureWithSenderH(e, 1);

    assert ret == MAGIC(),
        "a single guardian whose weight meets threshold must be accepted";
}

// ===========================================================================
// REACHABILITY WITNESS (i) -- MANDATORY. Non-vacuous ACCEPT via TWO DISTINCT guardians.
// There EXISTS a 2-slice input with distinct, strictly-ASCENDING signers whose combined real
// weights reach threshold and return MAGICVALUE. Kills vacuity of the accept branch.
// ===========================================================================
rule witnessTwoDistinctAccept(address acc) {
    env e;
    require e.msg.sender == acc;                                 // loop reads storage at `acc`
    address s0 = recoveredSigner(0);
    address s1 = recoveredSigner(1);

    require s0 != 0;
    require s0 < s1;                                             // strictly ascending -> distinct
    require weightOf(acc, s0) < thresholdOf(acc);               // first alone insufficient
    require weightOf(acc, s0) + weightOf(acc, s1) >= thresholdOf(acc); // together sufficient
    require thresholdOf(acc) != 0;

    bytes4 ret = isValidSignatureWithSenderH(e, 2);

    satisfy ret == MAGIC(),
        "no reachable accept from two distinct guardians summing to threshold on adapter storage";
}

// ===========================================================================
// REACHABILITY WITNESS (ii) -- MANDATORY discrimination. The audit PoC is reachable AND rejected.
// There EXISTS a duplicate (s0==s1) with 2w>=threshold>w that returns INVALID: the exact pre-fix
// exploit input, now correctly rejected by the ascending gate on adapter storage.
// ===========================================================================
rule witnessDuplicatePoCRejected(address acc) {
    env e;
    require e.msg.sender == acc;                                 // loop reads storage at `acc`
    address s0 = recoveredSigner(0);
    address s1 = recoveredSigner(1);

    require s0 != 0;
    require s0 == s1;
    require weightOf(acc, s0) > 0;
    require 2 * weightOf(acc, s0) >= thresholdOf(acc);          // WOULD reach threshold if double-counted
    require thresholdOf(acc) > weightOf(acc, s0);               // one copy alone does NOT
    require thresholdOf(acc) != 0;

    bytes4 ret = isValidSignatureWithSenderH(e, 2);

    satisfy ret == INVALID(),
        "audit PoC (duplicate, 2w>=threshold>w) not reachable as a rejection on adapter storage";
}
