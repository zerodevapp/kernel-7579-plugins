// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @author taek <leekt216@gmail.com>

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

/// @notice Double-count and ordering properties for the ERC1271 (`_validateSignature`) and
///         stateless (`_validateStatelessSignature`) paths of WeightedECDSASigner. Distinct from
///         WeightedECDSAAcceptSetHalmos, which exercised the legacy strictly-DESCENDING
///         `isValidSignatureWithSender` aggregation. THESE two paths use the current
///         strictly-ASCENDING guard (`lastSigner = 0`; reject on `signer <= lastSigner`) plus an
///         in-loop early-accept AND a separate ordering-gated last-signature branch — uncovered code.
///
/// MODELING (recover UNINTERPRETED — see TCB):
///   ECDSA.tryRecoverCalldata is a precompile Halmos cannot solve, so the RECOVERED SIGNER is the
///   symbolic variable: each 65-byte slice -> one symbolic address. sigCount = sig.length/65 is
///   modeled as a symbolic `count` in [1, N]. The loop body is a VERBATIM replica of
///   src/signers/WeightedECDSASigner.sol:
///     _validateSignature      :285-321 (sorted gate :289, weight add :299, early-accept :300, last :306-317)
///     _validateStatelessSignature :344-379 (sorted :347, weight :357, early-accept :358, last :364-376)
///   Both replicas share the identical accept/ordering logic; the only difference is the weight
///   source (real mapping for the installed ERC1271 path vs. memory arrays for the stateless path).
///   The ZeroWeightSigner revert on a non-last zero-weight signer is preserved so the harness only
///   accepts along the exact leaves the source accepts.
contract WeightedECDSAValidateSignatureHalmos is SymTest, Test {
    bytes4 constant ERC1271_MAGICVALUE = 0x1626ba7e;
    bytes4 constant ERC1271_INVALID = 0xffffffff;

    // Consistent per-address symbolic weight (installed ERC1271 path): same signer -> same weight.
    mapping(address => uint24) internal weightOf;

    uint256 constant N = 3; // bounded loop (sigCount): covers duplicate-adjacency + non-adjacent

    // ---------------------------------------------------------------------------------------------
    // Verbatim replica of _validateSignature (ERC1271 / installed path), lines 285-321.
    // Returns the bytes4 result AND `counted` = number of signers whose weight was added toward
    // totalWeight before returning (the accepting prefix on MAGICVALUE).
    // ---------------------------------------------------------------------------------------------
    function _runInstalled(address[N] memory signers, uint256 count, uint24 threshold)
        internal
        view
        returns (bytes4 result, uint256 counted)
    {
        if (threshold == 0) return (ERC1271_INVALID, 0); // :271-273
        if (count == 0) return (ERC1271_INVALID, 0); // :276-278

        uint256 totalWeight = 0;
        address lastSigner = address(0); // :282

        // Process all signatures except the last one (:285-303).
        // Loop unrolled over the concrete bound N with an explicit `i + 1 < count` guard so the
        // array offset stays CONCRETE (Halmos cannot index memory at a symbolic offset).
        for (uint256 i = 0; i < N; i++) {
            if (i + 1 >= count) break; // process all but the last
            address signer = signers[i]; // :286 recover, uninterpreted
            if (signer <= lastSigner) return (ERC1271_INVALID, i); // :289-291 sorted gate BEFORE count
            lastSigner = signer; // :292
            uint24 guardianWeight = weightOf[signer]; // :294
            if (guardianWeight == 0) revert(); // :296-298 ZeroWeightSigner
            totalWeight += guardianWeight; // :299
            if (totalWeight >= threshold) return (ERC1271_MAGICVALUE, i + 1); // :300-302
        }

        // Last signature (:305-318). Concrete-offset dispatch on count in [1, N].
        address last = count == 1 ? signers[0] : (count == 2 ? signers[1] : signers[2]); // :306
        if (last <= lastSigner) return (ERC1271_INVALID, count - 1); // :307-309 sorted gate
        uint24 lastWeight = weightOf[last]; // :310
        if (lastWeight == 0) return (ERC1271_INVALID, count - 1); // :311-314 (no revert on last)
        totalWeight += lastWeight; // :315
        if (totalWeight >= threshold) return (ERC1271_MAGICVALUE, count); // :316-318
        return (ERC1271_INVALID, count); // :320
    }

    // NOTE on _validateStatelessSignature (:344-379): its accept/ordering logic is byte-for-byte
    // identical to _validateSignature (ascending gate BEFORE count, in-loop early-accept, gated last
    // branch); only the weight SOURCE differs (memory-array _memoryGuardianWeight vs. real mapping).
    // Distinctness-of-the-counted-set is independent of the weight source, so the installed replica
    // below is the canonical proof for both paths. (The certora leg of this RACE inherits the real
    // contract and proves the stateless path directly with recover as a per-index ghost.)

    // =============================================================================================
    // PROPERTY (installed ERC1271 path): MAGICVALUE => the counted signers are pairwise DISTINCT.
    // The ascending ordering gate (:289 / :307) runs BEFORE the weight is added (:299 / :315), so no
    // duplicate address can have its weight counted twice. Asserted over the counted prefix only —
    // NOT a re-run of the summation (tautology guard).
    // =============================================================================================
    function check_MagicValueImpliesDistinctSigners_Installed(
        address s0,
        address s1,
        address s2,
        uint256 count,
        uint24 threshold,
        uint24 w0,
        uint24 w1,
        uint24 w2
    ) external {
        vm.assume(count >= 1 && count <= N);

        weightOf[s0] = w0;
        weightOf[s1] = w1;
        weightOf[s2] = w2;

        address[N] memory signers = [s0, s1, s2];
        (bytes4 result, uint256 counted) = _runInstalled(signers, count, threshold);

        if (result == ERC1271_MAGICVALUE) {
            if (counted >= 2 && s0 == s1) assert(false);
            if (counted >= 3) {
                assert(s0 != s2);
                assert(s1 != s2);
            }
        }
    }

    // VACUITY / REACHABILITY (installed accept path is LIVE): a 2-distinct-guardian input DOES accept.
    function check_MagicValueImpliesDistinctSigners_Installed_reachable(
        address s0,
        address s1,
        uint256 count,
        uint24 threshold,
        uint24 w0,
        uint24 w1
    ) external {
        vm.assume(count >= 1 && count <= N);
        weightOf[s0] = w0;
        weightOf[s1] = w1;
        weightOf[address(0)] = 0;

        address[N] memory signers = [s0, s1, address(0)];
        (bytes4 result,) = _runInstalled(signers, count, threshold);

        assert(result != ERC1271_MAGICVALUE); // expect CEX -> accept path reachable (non-vacuous)
    }

    // REACHABILITY (duplicate rejected, installed): one guardian weight w with 2w >= threshold > w;
    // duplicating the signature (s0 == s1) can never reach threshold — the ascending gate rejects
    // the equal second signer BEFORE its weight is counted.
    function check_DuplicateSignerRejected_Installed(address s, uint24 w, uint24 threshold) external {
        vm.assume(threshold != 0);
        vm.assume(w < threshold);
        vm.assume(uint256(w) * 2 >= threshold);

        weightOf[s] = w;
        address[N] memory signers = [s, s, s];

        (bytes4 result,) = _runInstalled(signers, 2, threshold);
        assertEq(result, ERC1271_INVALID);
    }
}
