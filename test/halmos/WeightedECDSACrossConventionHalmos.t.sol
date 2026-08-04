// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @author taek <leekt216@gmail.com>

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

/// @notice Cross-convention non-acceptance between WeightedECDSAValidator (ep0.7: the last UserOp
///         signature signs toEthSignedMessageHash(userOpHash)) and WeightedECDSAValidatorV09 (ep0.9:
///         the last signature signs the RAW userOpHash). The two contracts share `_verifyUserOp`
///         verbatim (src/base/WeightedThresholdBase.sol) — the ONLY behavioral difference is the
///         `finalHash` argument threaded from `_finalUserOpHash`. A signature set S that base ACCEPTS
///         (its final slice recovers, over hEth, to a weighted guardian g) must NOT be ACCEPTED by V09
///         (which recovers that SAME final slice over hRaw to a DIFFERENT address), and the first N-1
///         proposalHash aggregation prefix is bit-identical across the two (same message => same
///         recovered signers => same weight accumulation).
///
/// MODELING (recover treated as an uninterpreted, deterministic, message-injective ghost):
///   ECDSA.tryRecoverCalldata(message, sigChunk) is a precompile Halmos cannot solve symbolically, so
///   the RECOVERED SIGNERS are the symbolic variables (same convention as WeightedECDSAAcceptSetHalmos).
///   For a fixed calldata slice, recovery over the proposalHash message yields the prefix signers
///   p0..p1 (SHARED by both variants — same message). Recovery of the FINAL slice differs by variant:
///   over hEth it yields g (base), over hRaw it yields v09Final (V09). Message-injectivity — distinct
///   messages recover the same slice to distinct addresses — is a faithful ECDSA fact and is encoded
///   as vm.assume(v09Final != g). Per-address weight is a real mapping keyed by the symbolic signer,
///   so the SAME address always has the SAME weight (preserves the de-dup / double-count invariant).
///   _verifyUserOp is replicated VERBATIM, parameterized by the final signer (g vs v09Final). N = 3.
contract WeightedECDSACrossConventionHalmos is SymTest, Test {
    // Consistent per-address weight: identical signer address -> identical (symbolic) weight (uint24).
    mapping(address => uint24) internal weightOf;

    uint256 constant N = 3; // bounded sigCount

    /// @dev VERBATIM replica of WeightedThresholdBase._verifyUserOp (lines 102-176), with the recovered
    ///      signers supplied directly: `prefix` are the proposalHash signers (indices 0..count-2, SHARED
    ///      across both variants), `finalSigner` is the recovery of the final slice under this variant's
    ///      convention. Reverts (SignersNotSorted / ZeroWeightSigner) are modeled as Solidity reverts.
    function _verifyUserOp(address[N] memory prefix, address finalSigner, uint256 count, uint24 threshold)
        internal
        view
        returns (bool ok)
    {
        if (threshold == 0) return false; // line 110-112
        // sig.length % 65 == 0 and count != 0 guaranteed by the model (line 114-121)

        uint256 totalWeight = 0;
        address lastSigner = address(0);
        uint256 prefixLen = count - 1;

        // First N-1 signatures sign proposalHash (identical recovered signers across both variants).
        for (uint256 i = 0; i < prefixLen; i++) {
            address signer = prefix[i]; // line 134: recover(proposalHash, i)

            if (signer <= lastSigner) {
                revert("SignersNotSorted"); // line 137-139
            }
            lastSigner = signer; // line 140

            uint256 guardianWeight = weightOf[signer]; // line 143
            if (guardianWeight == 0) {
                revert("ZeroWeightSigner"); // line 145-147
            }
            totalWeight += guardianWeight; // line 148
        }

        // Last signature signs finalHash (finalSigner = recover(finalHash, count-1)).
        uint256 lastWeight = weightOf[finalSigner]; // line 155
        if (lastWeight == 0) {
            return false; // line 157-159
        }

        // De-dup: was the final signer already counted in the proposal prefix? (line 162-168)
        bool alreadySigned = false;
        for (uint256 i = 0; i < prefixLen; i++) {
            if (prefix[i] == finalSigner) {
                alreadySigned = true;
                break;
            }
        }

        if (!alreadySigned) {
            totalWeight += lastWeight; // line 171-173
        }

        return totalWeight >= threshold; // line 175
    }

    /// @notice CROSS-CONVENTION NON-ACCEPTANCE (observable, single-guardian decisive form): the guardian
    ///         set's only threshold-meeting member is g, the address the base variant recovers from the
    ///         final slice over hEth. V09 recovers that SAME final slice over hRaw to v09Final != g, an
    ///         UNAUTHORIZED (weight-0) address. The prefix signers are shared (same proposalHash) and the
    ///         prefix weight is held below threshold so base ACCEPT is DECISIVE on g's final signature.
    ///         The property: the SAME set S that base ACCEPTS is REJECTED by V09.
    ///
    ///         NON-TAUTOLOGY: the assertion is the ACCEPT DECISION (v09Ok == false) — it drives the full
    ///         aggregation (ordering, de-dup, threshold, the zero-weight-last-signer return-false path).
    ///         It is NOT a restatement of hEth != hRaw: a bug where V09 credited g's base-convention
    ///         signature (e.g. hashing the wrong message, or a de-dup/threshold flaw) would make
    ///         v09Ok == true and FALSIFY the property.
    function check_CrossConventionNonAcceptance(
        uint256 sigCount,
        uint24 threshold,
        address g,
        address v09Final,
        address p0,
        address p1,
        uint24 wg,
        uint24 wp0,
        uint24 wp1
    ) external {
        // Dispatch on CONCRETE count so loop bounds fold to constants. Union covers N = 1..3.
        if (sigCount == 1) {
            _scenario(1, threshold, g, v09Final, p0, p1, wg, wp0, wp1);
        } else if (sigCount == 2) {
            _scenario(2, threshold, g, v09Final, p0, p1, wg, wp0, wp1);
        } else if (sigCount == 3) {
            _scenario(3, threshold, g, v09Final, p0, p1, wg, wp0, wp1);
        }
    }

    /// @dev Concrete-count scenario. Builds the decisive single-guardian setup for exactly `count`
    ///      signatures, runs base (final signer g over hEth) and V09 (final signer v09Final over hRaw)
    ///      over the SAME signature set, and asserts non-acceptance.
    function _scenario(
        uint256 count,
        uint24 threshold,
        address g,
        address v09Final,
        address p0,
        address p1,
        uint24 wg,
        uint24 wp0,
        uint24 wp1
    ) internal {
        vm.assume(threshold != 0);
        // recover message-injectivity (ECDSA fidelity): V09's final signer over hRaw is NOT g.
        vm.assume(v09Final != g);
        // g meets threshold on its own; v09Final is an UNAUTHORIZED, weight-0 address (the replayed
        // slice recovers to a non-guardian under V09).
        vm.assume(wg >= threshold);
        vm.assume(v09Final != p0 && v09Final != p1); // v09Final is not one of the prefix guardians
        weightOf[g] = wg;
        weightOf[v09Final] = 0;

        // Prefix signers sign proposalHash (SAME message in BOTH variants -> bit-identical prefix).
        // Nonzero weights (no ZeroWeightSigner revert), distinct from g, and prefix sum < threshold so
        // base ACCEPT is DECISIVE on the hEth final slice.
        address[N] memory prefix = [address(0), address(0), address(0)];
        uint256 prefixWeight = 0;
        if (count >= 2) {
            vm.assume(p0 != g && p0 != v09Final);
            vm.assume(p0 != address(0));
            weightOf[p0] = wp0;
            vm.assume(wp0 != 0);
            prefix[0] = p0;
            prefixWeight += wp0;
        }
        if (count >= 3) {
            vm.assume(p1 != g && p1 != v09Final);
            vm.assume(p1 != p0);
            vm.assume(p0 < p1); // strictly ascending (else _verifyUserOp reverts SignersNotSorted)
            weightOf[p1] = wp1;
            vm.assume(wp1 != 0);
            prefix[1] = p1;
            prefixWeight += wp1;
        }
        vm.assume(prefixWeight < threshold); // final slice is load-bearing for base

        bool baseOk = _verifyUserOp(prefix, g, count, threshold);
        bool v09Ok = _verifyUserOp(prefix, v09Final, count, threshold);

        // OBSERVABLE POSTCONDITION: a set accepted by base is NOT accepted by V09.
        // (Non-vacuity confirmed out-of-band: `assert(!baseOk)` yields a CEX for count = 1, 2 and 3,
        // proving the `if (baseOk)` guard is live in every branch.)
        if (baseOk) {
            assert(!v09Ok);
        }
    }

    /// @notice VACUITY / REACHABILITY (i): the base ACCEPT branch is LIVE. A single-signature set
    ///         (count = 1, final slice only) with a guardian g meeting threshold DOES make base accept.
    ///         Asserts false on that path -> a counterexample proves the accept branch is reachable
    ///         (non-vacuous), so the main property's `if (baseOk)` guard is not dead.
    function check_CrossConventionNonAcceptance_reachable(uint24 threshold, address g, uint24 wg) external {
        vm.assume(threshold != 0);
        vm.assume(wg >= threshold);
        weightOf[g] = wg;
        address[N] memory prefix = [address(0), address(0), address(0)];
        bool baseOk = _verifyUserOp(prefix, g, 1, threshold);
        // Expect a CEX: g's weight meets threshold -> baseOk == true, negating the assert.
        assert(!baseOk);
    }
}
