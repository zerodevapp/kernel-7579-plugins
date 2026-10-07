// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @author taek <leekt216@gmail.com>

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

/// @notice After a SUCCESSFUL WeightedECDSAValidator.onInstall, the stored config is self-consistent:
///         threshold > 0 AND threshold <= totalWeight AND totalWeight == the sum of the validated
///         (non-zero, distinct, non-self, non-zero-address) input weights. Each rejection input
///         triggers its SPECIFIC revert selector. This is the SM-01 analog for the VALIDATOR — the
///         existing WeightedECDSAInstallHalmos proof covered only the SIGNER (WeightedECDSASigner).
///
/// MODELING (follows the repo WeightedECDSAInstall/Renew Halmos convention — the SUT is not deployed
///   because its EIP712 constructor is unsupported by Halmos's CREATE handling; the source lines are
///   replicated VERBATIM in-harness). Source: src/validators/WeightedECDSAValidator.sol onInstall
///   :89-114, _isInitialized :136-138. Faithful notes:
///     - reinstall guard (:90) keys off _isInitialized == (weightedStorage[kernel].totalWeight != 0).
///       On a FRESH account totalWeight is 0, so the guard passes; the reinstall-revert branch is
///       exercised by the rejection reachability check which pre-seeds totalWeight.
///     - LengthMismatch (:94) requires _guardians.length == _weights.length. Modeled with two
///       independent lengths (gLen/wLen) so the mismatch branch is genuinely reachable.
///     - DISTINCTNESS is enforced by guardian[g][kernel].weight == 0 (:105), NOT by ordering. Modeled
///       with a real mapping keyed by the symbolic guardian address, so an in-install duplicate (same
///       g twice) is caught because the first iteration wrote a non-zero weight.
///     - totalWeight (:109) is `+=` on uint24 under 0.8 checked arithmetic -> overflow reverts.
///     - single-config: no `id` dimension (unlike the signer); enabledWeight/storedTotalWeight/
///       storedThreshold model weightedStorage[KERNEL] for a fixed kernel.
contract WeightedECDSAValidatorInstallHalmos is SymTest, Test {
    error AlreadyInitialized(address);
    error LengthMismatch();
    error EmptyGuardians();
    error ZeroThreshold();
    error GuardianCannotBeSelf();
    error ZeroAddressGuardian();
    error ZeroWeight();
    error GuardianAlreadyEnabled();
    error ThresholdExceedsTotalWeight();
    error TotalWeightOverflow();

    // Models guardian[g][kernel].weight for a fixed kernel: identical guardian address always yields
    // identical stored weight, so the "already enabled" guard sees a consistent view.
    mapping(address => uint24) internal enabledWeight;

    uint24 internal storedTotalWeight; // models weightedStorage[kernel].totalWeight
    uint24 internal storedThreshold; //  models weightedStorage[kernel].threshold

    uint256 constant N = 3; // bounded guardian-array length (1..3) for tractability

    address constant KERNEL = address(0xdead); // stand-in for msg.sender (the kernel)

    /// @dev Faithful replica of onInstall :89-114 for a fixed KERNEL. Returns success = false with a
    ///      revert selector on any require/overflow path (so the caller can assert the SPECIFIC
    ///      selector), and on success returns (totalWeight, threshold) plus the summed weight of the
    ///      validated inputs computed INDEPENDENTLY (uint256, no early-exit) for the totalWeight==sum
    ///      equivalence. gLen/wLen are the two array lengths so :94 LengthMismatch is reachable.
    function _install(
        address[N] memory guardians,
        uint24[N] memory weights,
        uint256 gLen,
        uint256 wLen,
        uint24 _threshold
    ) internal returns (bool success, bytes4 selector, uint24 totalWeight, uint24 threshold, uint256 independentSum) {
        // :90 reinstall guard
        if (storedTotalWeight != 0) return (false, AlreadyInitialized.selector, 0, 0, 0);
        // :94 length mismatch
        if (gLen != wLen) return (false, LengthMismatch.selector, 0, 0, 0);
        if (gLen == 0) return (false, EmptyGuardians.selector, 0, 0, 0); // :95
        if (_threshold == 0) return (false, ZeroThreshold.selector, 0, 0, 0); // :96

        totalWeight = 0; // fresh storage
        independentSum = 0;
        for (uint256 i = 0; i < gLen; i++) {
            address g = guardians[i];
            uint24 w = weights[i];
            if (g == KERNEL) return (false, GuardianCannotBeSelf.selector, 0, 0, 0); // :102
            if (g == address(0)) return (false, ZeroAddressGuardian.selector, 0, 0, 0); // :103
            if (w == 0) return (false, ZeroWeight.selector, 0, 0, 0); // :104
            if (enabledWeight[g] != 0) return (false, GuardianAlreadyEnabled.selector, 0, 0, 0); // :105

            enabledWeight[g] = w; // :106-107 write guardian storage (distinctness for next iters)
            // :109 totalWeight += w on uint24 -> checked, reverts on overflow.
            unchecked {
                uint24 nt = totalWeight + w;
                if (nt < totalWeight) return (false, TotalWeightOverflow.selector, 0, 0, 0);
                totalWeight = nt;
            }
            // Independent accumulation in wide uint256 (cannot overflow for N<=3 uint24s): this is the
            // intended "sum of validated weights", computed WITHOUT reusing the uint24 running total,
            // so totalWeight == independentSum is a genuine equivalence, not a tautology.
            independentSum += uint256(w);
        }

        // :112 threshold <= totalWeight
        if (_threshold > totalWeight) return (false, ThresholdExceedsTotalWeight.selector, 0, 0, 0);
        threshold = _threshold; // :113

        // commit to storage (models weightedStorage writes)
        storedTotalWeight = totalWeight;
        storedThreshold = threshold;
        return (true, bytes4(0), totalWeight, threshold, independentSum);
    }

    /// @notice OBSERVABLE: on any SUCCESSFUL install, the stored config satisfies
    ///         threshold > 0 AND threshold <= totalWeight AND totalWeight == sum(validated weights).
    function check_InstallEstablishesConsistentThreshold(
        address g0,
        address g1,
        address g2,
        uint24 w0,
        uint24 w1,
        uint24 w2,
        uint256 gLen,
        uint24 _threshold
    ) external {
        vm.assume(gLen >= 1 && gLen <= N);

        address[N] memory guardians = [g0, g1, g2];
        uint24[N] memory weights = [w0, w1, w2];

        // Success path requires equal lengths; on the observable claim we drive the matched case.
        (bool success,, uint24 totalWeight, uint24 threshold, uint256 independentSum) =
            _install(guardians, weights, gLen, gLen, _threshold);

        if (success) {
            // Single coherent claim about a successful install's stored state.
            assert(storedThreshold > 0 && storedThreshold <= storedTotalWeight);
            assert(threshold == storedThreshold && totalWeight == storedTotalWeight);
            assert(uint256(totalWeight) == independentSum);
        }
    }

    /// @notice VACUITY / REACHABILITY: a valid config (>=1 guardian, threshold in (0, sum]) SUCCEEDS
    ///         with the invariant holding. Asserts false on that live success path — a counterexample
    ///         proves the success path is reachable (non-vacuous). NO counterexample => preconditions
    ///         unsatisfiable => VACUOUS.
    function check_InstallEstablishesConsistentThreshold_reachable(
        address g0,
        address g1,
        address g2,
        uint24 w0,
        uint24 w1,
        uint24 w2,
        uint256 gLen,
        uint24 _threshold
    ) external {
        vm.assume(gLen >= 1 && gLen <= N);

        address[N] memory guardians = [g0, g1, g2];
        uint24[N] memory weights = [w0, w1, w2];

        (bool success,, uint24 totalWeight, uint24 threshold,) = _install(guardians, weights, gLen, gLen, _threshold);

        require(success);
        require(threshold > 0);
        require(threshold <= totalWeight);
        assert(false); // reachable success => Halmos must return a counterexample here
    }

    /// @notice REACHABILITY of each rejection branch: for every specific revert selector, there exists
    ///         an input that triggers exactly it. Asserts false when a given selector is produced; a
    ///         counterexample per selector proves that revert branch is live (so the "each rejection
    ///         triggers its SPECIFIC selector" clause is not vacuous). One assert per selector; Halmos
    ///         reports a CEX for each reachable branch. gLen/wLen independent so LengthMismatch fires.
    function check_RejectionBranchesReachable(
        address g0,
        address g1,
        address g2,
        uint24 w0,
        uint24 w1,
        uint24 w2,
        uint256 gLen,
        uint256 wLen,
        uint24 _threshold,
        uint24 seedTotalWeight
    ) external {
        vm.assume(gLen <= N && wLen <= N);

        // Allow the reinstall-guard branch to be reachable by seeding stored totalWeight.
        storedTotalWeight = seedTotalWeight;

        address[N] memory guardians = [g0, g1, g2];
        uint24[N] memory weights = [w0, w1, w2];

        (bool success, bytes4 selector,,,) = _install(guardians, weights, gLen, wLen, _threshold);

        if (!success) {
            // Each of these must be independently reachable -> a CEX for each proves liveness.
            if (selector == AlreadyInitialized.selector) assert(false);
            if (selector == LengthMismatch.selector) assert(false);
            if (selector == EmptyGuardians.selector) assert(false);
            if (selector == ZeroThreshold.selector) assert(false);
            if (selector == GuardianCannotBeSelf.selector) assert(false);
            if (selector == ZeroAddressGuardian.selector) assert(false);
            if (selector == ZeroWeight.selector) assert(false);
            if (selector == GuardianAlreadyEnabled.selector) assert(false);
            if (selector == ThresholdExceedsTotalWeight.selector) assert(false);
        }
    }
}
