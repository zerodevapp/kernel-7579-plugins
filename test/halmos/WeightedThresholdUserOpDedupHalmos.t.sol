// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @author taek <leekt216@gmail.com>

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

/// @notice Dedup / double-count property for the SPLIT-SIG UserOp path of WeightedThresholdBase
///         (`_verifyUserOp`, src/base/WeightedThresholdBase.sol:102-176). NEW code — no existing
///         proof touches the split-sig path (WeightedECDSAValidateSignatureHalmos covers only the
///         single-hash `_validateSignature`/`_validateStatelessSignature` sorted paths).
///
/// MODELING (recover UNINTERPRETED — see TCB):
///   ECDSA.tryRecoverCalldata is a precompile Halmos cannot solve, so the RECOVERED SIGNER is the
///   symbolic variable. CRITICAL: the N-1 proposal slices recover over `proposalHash` while the
///   FINAL slice recovers over `finalHash` (a DIFFERENT message) — so the final signer is an
///   INDEPENDENT symbolic address. The harness lets the adversary CHOOSE the final signer equal to
///   any proposal signer (that IS the double-count attack the dedup :161-173 defends against).
///   Weight is a real per-address mapping keyed by recovered address (same address -> same weight).
///   sigCount is modeled as symbolic `count` in [1, N]; the loop is unrolled over concrete N with an
///   `i + 1 < count` guard so array offsets stay concrete (Halmos can't index memory symbolically).
///   The ascending gate REVERTS (SignersNotSorted) and a non-last zero-weight proposal signer REVERTS
///   (ZeroWeightSigner) — preserved verbatim so the harness only accepts along source-accepting leaves.
///
/// N = 3: up to 2 proposal signers + 1 final signer — the smallest bound that exhibits both a
/// multi-signer ascending proposal set AND the final==proposal double-count case.
contract WeightedThresholdUserOpDedupHalmos is SymTest, Test {
    // Consistent per-address symbolic weight: same recovered signer -> same weight.
    mapping(address => uint256) internal weightOf;

    uint256 constant N = 3;

    // ---------------------------------------------------------------------------------------------
    // Verbatim replica of WeightedThresholdBase._verifyUserOp (:102-176).
    //   proposal[0..count-2] recover over proposalHash (independent symbolic addresses).
    //   `finalSigner` recovers over finalHash (independent, adversary-chosen).
    //   count == sigCount in [1, N]: count-1 proposal signers + 1 final signer.
    // Reverts (via Solidity revert) mirror _revertSignersNotSorted / _revertZeroWeightSigner.
    // ---------------------------------------------------------------------------------------------
    function _runUserOp(address[N] memory proposal, address finalSigner, uint256 count, uint256 threshold)
        internal
        view
        returns (bool ok)
    {
        if (threshold == 0) return false; // :110-112
        // sig.length % 65 == 0 and sigCount != 0 modeled by count in [1, N] (:114-121)

        uint256 totalWeight = 0;
        address lastSigner = address(0); // :125

        // proposalSigners[0..count-2] — the N-1 proposal set (:128).
        address[N] memory proposalSigners;
        uint256 proposalLen = count - 1;

        // Process all signatures except the last one — they sign proposalHash (:133-150).
        // Unrolled over concrete N with an `i + 1 < count` guard to keep offsets concrete.
        for (uint256 i = 0; i < N; i++) {
            if (i + 1 >= count) break; // process all but the last (i < sigCount - 1)
            address signer = proposal[i]; // :134 recover(proposalHash, ...), uninterpreted
            if (signer <= lastSigner) revert(); // :137-139 SignersNotSorted REVERT (BEFORE count)
            lastSigner = signer; // :140
            proposalSigners[i] = signer; // :141
            uint256 guardianWeight = weightOf[signer]; // :143
            if (guardianWeight == 0) revert(); // :145-147 ZeroWeightSigner REVERT
            totalWeight += guardianWeight; // :148 NO early return :149
        }

        // Last signature signs finalHash (:153) — independent recovery.
        address last = finalSigner; // :153 recover(finalHash, ...), uninterpreted & adversary-chosen
        uint256 lastWeight = weightOf[last]; // :155
        if (lastWeight == 0) return false; // :157-159 (no revert on last)

        // Dedup: was the finalHash signer among the proposalHash signers? (:161-168)
        bool alreadySigned = false;
        for (uint256 i = 0; i < N; i++) {
            if (i >= proposalLen) break;
            if (proposalSigners[i] == last) {
                alreadySigned = true;
                break;
            }
        }

        if (!alreadySigned) {
            totalWeight += lastWeight; // :171-173 add only if not already counted
        }

        return totalWeight >= threshold; // :175
    }

    // =============================================================================================
    // DISPATCHED PROPERTY (observable, contrapositive double-count case):
    //   Final signer == the single proposal signer; one guardian weight w with w < threshold <= 2w.
    //   If the dedup :161-173 works, that lone guardian's weight is counted ONCE (not doubled) so the
    //   split sig MUST NOT accept. A broken dedup would double w to 2w >= threshold and return true.
    //   Asserted as an observable outcome (result must be false) — NOT a re-run of the dedup loop.
    // =============================================================================================
    function check_FinalEqualsProposalNotDoubleCounted(address g, uint256 w, uint256 threshold) external {
        vm.assume(threshold != 0);
        vm.assume(w < threshold); // one copy is below threshold
        vm.assume(w * 2 >= threshold); // two copies WOULD reach it — dedup is what prevents accept
        vm.assume(w < type(uint128).max); // avoid overflow noise in the doubling arithmetic

        weightOf[g] = w;

        // count = 2: one proposal signer (g over proposalHash) + final signer (g over finalHash).
        address[N] memory proposal = [g, address(0), address(0)];
        bool ok = _runUserOp(proposal, g, 2, threshold);

        assertEq(ok, false); // dedup fires -> weight counted once -> below threshold -> reject
    }

    // ---------------------------------------------------------------------------------------------
    // VACUITY / REACHABILITY (accept path is LIVE): a legitimate 2-DISTINCT-guardian split sig
    // (one proposal signer + a DIFFERENT final signer, weights summing >= threshold) DOES accept.
    // If this found no CEX the preconditions of the accept branch would be unsatisfiable (vacuous).
    // ---------------------------------------------------------------------------------------------
    function check_FinalEqualsProposalNotDoubleCounted_reachable(
        address gp,
        address gf,
        uint256 wp,
        uint256 wf,
        uint256 threshold
    ) external {
        vm.assume(gp != gf); // two DISTINCT guardians
        vm.assume(gp > address(0)); // proposal signer must beat lastSigner = 0 (ascending gate)
        vm.assume(threshold != 0);
        vm.assume(wp != 0 && wf != 0);
        vm.assume(wp < type(uint128).max && wf < type(uint128).max);
        vm.assume(wp + wf >= threshold); // combined weight reaches threshold

        weightOf[gp] = wp;
        weightOf[gf] = wf;

        // count = 2: proposal signer gp + final signer gf (distinct).
        address[N] memory proposal = [gp, address(0), address(0)];
        bool ok = _runUserOp(proposal, gf, 2, threshold);

        assert(!ok); // expect CEX -> accept path reachable (non-vacuous)
    }

    // ---------------------------------------------------------------------------------------------
    // DISCRIMINATION: proves the dedup is load-bearing. Same lone guardian, count = 3 (two proposal
    // slices would BOTH be g — but the ascending gate REVERTS on the equal second proposal signer,
    // so this input can never accept regardless of dedup). Confirms the ascending REVERT for the
    // proposal set on the split path. (The dedup-specific discrimination is the dispatched property
    // above: without dedup, count=2 final==proposal WOULD accept.)
    // ---------------------------------------------------------------------------------------------
    function check_DuplicateProposalSignersRevert(address g, uint256 w, uint256 threshold) external {
        vm.assume(threshold != 0);
        vm.assume(w != 0 && w < type(uint128).max);
        weightOf[g] = w;

        address[N] memory proposal = [g, g, address(0)];
        // count = 3: proposal signers [g, g] + final. The equal second proposal signer trips the
        // ascending gate -> revert. Halmos treats the revert as a non-accepting leaf; there is no
        // path where this returns true.
        (bool success,) = address(this).staticcall(abi.encodeCall(this.callRunUserOp, (proposal, g, 3, threshold)));
        assertEq(success, false); // ascending gate reverts -> no accepting path
    }

    /// @dev External wrapper so the discrimination check can observe the revert via staticcall.
    function callRunUserOp(address[N] memory proposal, address finalSigner, uint256 count, uint256 threshold)
        external
        view
        returns (bool)
    {
        return _runUserOp(proposal, finalSigner, count, threshold);
    }
}
