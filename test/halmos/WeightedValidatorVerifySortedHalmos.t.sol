// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @author taek <leekt216@gmail.com>

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

/// @notice ADAPTER-LEVEL proof for WeightedECDSAValidator.isValidSignatureWithSender, which
///         delegates to the SHARED WeightedThresholdBase._verifySorted on the VALIDATOR's storage
///         layout (single-config guardian set: threshold from weightedStorage[msg.sender].threshold,
///         weight from guardian[signer][msg.sender].weight, cfg = bytes32(0)). Establishes the shared
///         core is sound on the validator adapter, not just on WeightedECDSASigner — the core reason
///         for the refactor. Distinct from:
///           - WeightedECDSAValidateSignatureHalmos: proves the SIGNER's _validateSignature paths.
///           - WeightedECDSAAcceptSetHalmos: legacy strictly-DESCENDING variant (stale guard model).
///
/// MODELING (recover UNINTERPRETED — see TCB):
///   ECDSA.tryRecoverCalldata is a precompile Halmos cannot solve, so the RECOVERED SIGNER is the
///   symbolic variable: each 65-byte slice -> one symbolic address, sigCount = sig.length/65 modeled
///   as a symbolic `count` in [1, N]. Per-signer weight is looked up through a real mapping keyed by
///   the symbolic address, so the SAME address always yields the SAME weight (the constraint that
///   makes the duplicate-signer case faithful — mirrors guardian[signer][account].weight).
///   The body is a VERBATIM replica of WeightedThresholdBase._verifySorted (src/base/WeightedThreshold-
///   Base.sol:38-93) as reached through the validator adapter (WeightedECDSAValidator.sol:171-178):
///     :43-45  threshold == 0        -> false
///     :47-50  sigCount == 0         -> false
///     :54     lastSigner = address(0)
///     :57-75  loop over first sigCount-1: :61 ascending gate `signer <= lastSigner` BEFORE count,
///             :66 weight via _guardianWeight, :68-70 non-last zero-weight REVERTS ZeroWeightSigner,
///             :71 add, :72 `>=` early-accept
///     :78-90  last sig: :79 ascending gate, :82 weight, :84-86 last zero-weight returns false (no
///             revert), :87 add, :88 `>=` accept
///     :92     fall-through false
contract WeightedValidatorVerifySortedHalmos is SymTest, Test {
    bytes4 constant ERC1271_MAGICVALUE = 0x1626ba7e;
    bytes4 constant ERC1271_INVALID = 0xffffffff;

    // Consistent per-address symbolic weight (validator single-config path): mirrors
    // guardian[signer][msg.sender].weight — same signer -> same weight (uint24, the storage width).
    mapping(address => uint24) internal weightOf;

    uint256 constant N = 3; // bounded loop (sigCount): covers duplicate-adjacency + non-adjacent

    // ---------------------------------------------------------------------------------------------
    // Verbatim replica of WeightedThresholdBase._verifySorted as reached via the validator adapter.
    // Returns the bytes4 that isValidSignatureWithSender returns AND `counted` = number of signers
    // whose weight was added toward totalWeight before returning (the accepting prefix on MAGICVALUE).
    // Loop is unrolled over the concrete bound N with an explicit `i + 1 < count` guard so the array
    // offset stays CONCRETE (Halmos cannot index memory at a symbolic offset).
    // ---------------------------------------------------------------------------------------------
    function _verifySorted(address[N] memory signers, uint256 count, uint24 threshold)
        internal
        view
        returns (bytes4 result, uint256 counted)
    {
        if (threshold == 0) return (ERC1271_INVALID, 0); // :43-45
        if (count == 0) return (ERC1271_INVALID, 0); // :47-50

        uint256 totalWeight = 0;
        address lastSigner = address(0); // :54

        // Process all signatures except the last one (:57-75).
        for (uint256 i = 0; i < N; i++) {
            if (i + 1 >= count) break; // process all but the last
            address signer = signers[i]; // :58 recover, uninterpreted
            if (signer <= lastSigner) return (ERC1271_INVALID, i); // :61-63 ascending gate BEFORE count
            lastSigner = signer; // :64
            uint24 guardianWeight = weightOf[signer]; // :66 _guardianWeight
            if (guardianWeight == 0) revert(); // :68-70 _revertZeroWeightSigner (MUST revert)
            totalWeight += guardianWeight; // :71
            if (totalWeight >= threshold) return (ERC1271_MAGICVALUE, i + 1); // :72-74
        }

        // Last signature (:78-90). Concrete-offset dispatch on count in [1, N].
        address last = count == 1 ? signers[0] : (count == 2 ? signers[1] : signers[2]); // :78
        if (last <= lastSigner) return (ERC1271_INVALID, count - 1); // :79-81 ascending gate
        uint24 lastWeight = weightOf[last]; // :82
        if (lastWeight == 0) return (ERC1271_INVALID, count - 1); // :84-86 (no revert on last)
        totalWeight += lastWeight; // :87
        if (totalWeight >= threshold) return (ERC1271_MAGICVALUE, count); // :88-90
        return (ERC1271_INVALID, count); // :92
    }

    // =============================================================================================
    // PROPERTY (validator adapter, ERC1271 path): MAGICVALUE => the counted signers are pairwise
    // DISTINCT. The ascending ordering gate (:61 / :79) runs BEFORE weight is added (:71 / :87), so
    // no duplicate address can have its weight counted twice. Asserted over the counted prefix only
    // — NOT a re-run of the summation (tautology guard).
    // =============================================================================================
    function check_MagicValueImpliesDistinctSigners_Validator(
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
        (bytes4 result, uint256 counted) = _verifySorted(signers, count, threshold);

        if (result == ERC1271_MAGICVALUE) {
            if (counted >= 2 && s0 == s1) assert(false); // s0,s1 both counted -> must differ
            if (counted >= 3) {
                assert(s0 != s2);
                assert(s1 != s2);
            }
        }
    }

    // VACUITY / REACHABILITY (i): the validator accept path is LIVE — a 2-distinct-guardian input
    // with weights summing >= threshold DOES return MAGICVALUE. Asserts false on that path; a CEX
    // proves the MAGICVALUE branch of the main property is reachable (non-vacuous accept).
    function check_MagicValueImpliesDistinctSigners_Validator_reachable(
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
        weightOf[address(0)] = 0; // s2 slot unused in this witness

        address[N] memory signers = [s0, s1, address(0)];
        (bytes4 result,) = _verifySorted(signers, count, threshold);

        assert(result != ERC1271_MAGICVALUE); // expect CEX -> accept path reachable (non-vacuous)
    }

    // REACHABILITY / DISCRIMINATION (ii): one validator guardian of weight w with 2w >= threshold > w;
    // a DUPLICATED signature (s0 == s1 == s) can NEVER reach threshold — the ascending gate (:61)
    // rejects the equal second signer BEFORE its weight is counted, so the result is ERC1271_INVALID.
    // This is the duplicate-signer auth-bypass bug class, proved blocked on the validator's layout.
    function check_DuplicateSignerRejected_Validator(address s, uint24 w, uint24 threshold) external {
        vm.assume(threshold != 0);
        vm.assume(w < threshold); // one signature alone is below threshold
        vm.assume(uint256(w) * 2 >= threshold); // ...but counting it twice would reach it

        weightOf[s] = w; // the single guardian
        address[N] memory signers = [s, s, s];

        (bytes4 result,) = _verifySorted(signers, 2, threshold);

        assertEq(result, ERC1271_INVALID); // duplicate must be rejected
    }
}
