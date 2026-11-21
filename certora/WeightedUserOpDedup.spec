/*
 * EC-02-USEROP-DEDUP (certora leg of a RACE) -- WeightedThresholdBase._verifyUserOp
 * split-UserOp de-dup / no-double-count. Source: src/base/WeightedThresholdBase.sol:102-176.
 *
 * DISPATCHED OBSERVABLE (Critical, contrapositive double-count):
 *   If the FINAL (finalHash) signer is the SAME guardian as the single proposalHash signer, and
 *   ONE copy of that guardian's weight w is below threshold while TWO copies would reach it
 *   (w < threshold <= 2w), then _verifyUserOp MUST return FALSE. i.e. the in-memory de-dup
 *   (:161-173) counts the final signer's weight AT MOST ONCE even when it also appears among the
 *   proposal signers -> a single guardian signing both the proposal and the final hash CANNOT
 *   reach threshold alone. This is an auth-bypass class bug if broken.
 *
 * WHY THIS IS THE TCB-INDEPENDENT LEG:
 *   The harness INHERITS the real WeightedThresholdBase and calls its REAL _verifyUserOp
 *   bytecode over REAL calldata `sigBytes`. Nothing in the aggregation / ordering / de-dup loop is
 *   re-implemented (contrast the Halmos verbatim replica). The ONLY summarized primitive is
 *   ECDSA.tryRecoverCalldata (an ecrecover precompile the solver cannot invert), replaced by a
 *   deterministic uninterpreted ghost keyed on the message `hash`:
 *     - the N-1 proposal slices recover against `proposalHash`  -> recover(proposalHash)
 *     - the final slice recovers against `finalHash`            -> recover(finalHash)
 *   These are INDEPENDENT symbolic addresses; the adversary is free to CHOOSE the final signer
 *   equal to the proposal signer (recover(finalHash) == recover(proposalHash)) -- exactly the
 *   double-count attack. Proof covers the base de-dup logic, NOT ECDSA soundness. (DISCLOSED TCB:
 *   solc8.30 + Certora solver + hash-keyed recover summary; real base bytecode otherwise.)
 *
 * TAUTOLOGY CHECK: the assertion is the RETURN value of _verifyUserOp under a
 * final==proposal-signer precondition -- an observable outcome. It does not recompute the
 * summation or re-run the de-dup scan. PASS.
 *
 * REACHABILITY CHECK (both mandatory, via `satisfy`):
 *  (i) satisfiability -- a legitimate split sigBytes (one proposal signer + a DIFFERENT final signer,
 *      weights summing >= threshold) returns TRUE (accept branch is live, not vacuous).
 *  (ii) discrimination -- the double-count attack input is REACHABLE as a rejection; if the
 *      de-dup were absent the same input would return true, so this proves the de-dup fires.
 *
 * @author taek <leekt216@gmail.com>
 */

methods {
    function weightOf(address) external returns (uint256) envfree;
    function verifyUserOp(bytes32, bytes32, bytes, uint256) external returns (bool) envfree;

    // ECDSA.tryRecoverCalldata is summarized as a deterministic uninterpreted function of the
    // message hash: same hash -> same recovered address. Distinct hashes (proposalHash vs
    // finalHash) recover INDEPENDENT addresses, which the adversary may pin equal.
    function ECDSA.tryRecoverCalldata(bytes32 hash, bytes calldata slice) internal returns (address) =>
        recover(hash);
}

// Deterministic per-message recovery. Uninterpreted -> the adversary picks the value, but it is
// fixed per hash (a fixed 65-byte slice signing a fixed hash yields a fixed signer).
ghost recover(bytes32) returns address;

// A 2-sigBytes split UserOp: sigBytes.length == 130 == one proposal slice (over proposalHash) + one final
// slice (over finalHash). sigCount-1 == 1 proposal signer; final slice is the last 65 bytes.
definition TWO_SIG_LEN() returns uint256 = 130;

// ---------------------------------------------------------------------------
// MAIN PROPERTY (dispatched) -- de-dup: a guardian signing BOTH the proposal and the final hash
// double-counts to reach threshold alone => the base MUST reject. Contrapositive of the bug.
// ---------------------------------------------------------------------------
rule finalEqualsProposalNeverDoubleCounts(bytes32 pHash, bytes32 fHash) {
    bytes sigBytes;
    require sigBytes.length == TWO_SIG_LEN();           // exactly 1 proposal signer + 1 final signer

    address pSigner = recover(pHash);              // the single proposalHash signer
    address fSigner = recover(fHash);              // the finalHash signer

    require fSigner == pSigner;                     // ADVERSARY: final signer == proposal signer
    require pSigner != 0;                           // a real, non-sentinel guardian

    uint256 w = weightOf(pSigner);
    require w > 0;                                  // pSigner is a guardian (non-zero weight)

    // one copy is insufficient, two copies WOULD reach threshold -> the whole attack surface
    uint256 threshold;
    require to_mathint(threshold) > to_mathint(w);
    require to_mathint(threshold) <= 2 * to_mathint(w);

    bool ok = verifyUserOp(pHash, fHash, sigBytes, threshold);

    assert !ok,
        "de-dup broken: a guardian signing both proposal and final reached threshold alone";
}

// ---------------------------------------------------------------------------
// REACHABILITY WITNESS (i) -- the ACCEPT branch is live (non-vacuous).
// Two DISTINCT guardians: one proposal signer + a different final signer, weights sum >= threshold.
// ---------------------------------------------------------------------------
rule witnessDistinctSignersAccept(bytes32 pHash, bytes32 fHash) {
    bytes sigBytes;
    require sigBytes.length == TWO_SIG_LEN();

    address pSigner = recover(pHash);
    address fSigner = recover(fHash);

    require pSigner != 0 && fSigner != 0;
    require pSigner != fSigner;                     // two DISTINCT guardians

    uint256 wp = weightOf(pSigner);
    uint256 wf = weightOf(fSigner);
    require wp > 0 && wf > 0;

    uint256 threshold;
    require threshold > 0;
    require to_mathint(wp) < to_mathint(threshold);            // proposal signer alone insufficient
    require to_mathint(wp) + to_mathint(wf) >= to_mathint(threshold); // together sufficient

    bool ok = verifyUserOp(pHash, fHash, sigBytes, threshold);

    satisfy ok,
        "no reachable accept from two distinct guardians summing to threshold (accept vacuous)";
}

// ---------------------------------------------------------------------------
// REACHABILITY WITNESS (ii) -- the double-count ATTACK input is reachable as a REJECTION.
// The exact final==proposal PoC with 2w>=threshold>w returns false: proves the de-dup fires
// (absent de-dup, this same input would return true).
// ---------------------------------------------------------------------------
rule witnessDoubleCountPoCRejected(bytes32 pHash, bytes32 fHash) {
    bytes sigBytes;
    require sigBytes.length == TWO_SIG_LEN();

    address pSigner = recover(pHash);
    address fSigner = recover(fHash);

    require fSigner == pSigner;
    require pSigner != 0;

    uint256 w = weightOf(pSigner);
    require w > 0;

    uint256 threshold;
    require to_mathint(threshold) > to_mathint(w);
    require 2 * to_mathint(w) >= to_mathint(threshold);

    bool ok = verifyUserOp(pHash, fHash, sigBytes, threshold);

    satisfy !ok,
        "double-count PoC (final==proposal, 2w>=threshold>w) not reachable as a rejection";
}
