// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ERC1271_MAGICVALUE, ERC1271_INVALID} from "src/types/Constants.sol";
import {WeightedECDSAValidator} from "src/validators/WeightedECDSAValidator.sol";

/// @title WeightedThresholdBaseHarness
/// @author taek <leekt216@gmail.com>
/// @notice Certora harness for the ERC-1271 acceptance path of the REAL WeightedECDSAValidator
///         adapter over the SHARED WeightedThresholdBase._verifySorted
///         (src/base/WeightedThresholdBase.sol:38-93, adapter
///         src/validators/WeightedECDSAValidator.sol:171-178).
///
///         Distinct from certora/harness/WeightedECDSAHarness.sol (EC-01): that harness is a
///         STANDALONE re-implementation with a fabricated `threshold`/`weightOf` and targets the
///         OLD strictly-DESCENDING validator. THIS harness inherits the real
///         WeightedECDSAValidator and drives the aggregation on the adapter's REAL storage
///         layout: threshold from `weightedStorage[account].threshold` and each weight from the
///         inherited `_guardianWeight(bytes32(0), account, signer)` -> `guardian[signer][account]
///         .weight`. That establishes the shared core is sound on the validator's storage layout
///         (the point of the refactor), TCB-independent from the halmos verbatim-replica leg.
///
///         ECDSA.tryRecoverCalldata is elliptic-curve recovery the symbolic engine cannot invert
///         and is called inline inside the inherited _verifySorted (no override seam), so the loop
///         is re-expressed here VERBATIM against the shared base's semantics with recovery routed
///         through the overridable `_recoverSigner(i)` (summarized in the spec as an
///         UNINTERPRETED, DETERMINISTIC-in-index ghost: same 65-byte slice sig[i*65:(i+1)*65] ->
///         same recovered address). Every OTHER line -- the ascending gate `signer <= lastSigner`
///         at :61/:79 that runs BEFORE the weight is counted at :71/:87, the non-last zero-weight
///         REVERT at :68-70, the last zero-weight `return false` at :84-86, the `>=` threshold
///         at :72/:88 -- is a byte-for-byte mirror of WeightedThresholdBase._verifySorted, and
///         the weight/threshold reads hit the real validator storage. The proof covers the
///         ordering/threshold aggregation on the adapter's storage, NOT ECDSA soundness.
contract WeightedThresholdBaseHarness is WeightedECDSAValidator {
    /// @dev Uninterpreted stand-in for ECDSA.tryRecoverCalldata(hash, sig[i*65:(i+1)*65]).
    ///      Certora replaces this with the `recoveredSigner(i)` ghost declared in the spec: a
    ///      symbolic address chosen by the adversary but DETERMINISTIC in the loop index `i`,
    ///      which is a 1:1 image of the fixed 65-byte slice offset. A duplicated slice therefore
    ///      recovers the SAME address; the spec's `s_i == s_j` precondition forces exactly that
    ///      collision (the audit PoC). Body is a compile-only placeholder never executed.
    function _recoverSigner(uint256 i) internal view virtual returns (address) {
        return address(uint160(i + 1));
    }

    /// @notice Byte-for-byte mirror of WeightedThresholdBase._verifySorted (:38-93) reading the
    ///         REAL adapter storage: `weightedStorage[msg.sender].threshold` for the threshold and
    ///         the inherited real `_guardianWeight(bytes32(0), msg.sender, signer)` for each
    ///         weight. Only ECDSA.tryRecoverCalldata is swapped for the summarized _recoverSigner.
    /// @param sigCount number of 65-byte slices = data.length / 65.
    /// @return ERC1271_MAGICVALUE on accept, ERC1271_INVALID otherwise (mirrors the adapter's
    ///         isValidSignatureWithSender wrapper at :171-178).
    function isValidSignatureWithSenderH(uint256 sigCount) external view returns (bytes4) {
        address account = msg.sender;
        uint256 threshold = weightedStorage[account].threshold;

        // _verifySorted body -------------------------------------------------
        if (threshold == 0) {
            return ERC1271_INVALID;
        }
        if (sigCount == 0) {
            return ERC1271_INVALID;
        }

        uint256 totalWeight = 0;
        address signer;
        address lastSigner = address(0);

        // Process all signatures except the last one.
        for (uint256 i = 0; i < sigCount - 1; i++) {
            signer = _recoverSigner(i);

            // Ascending gate (EC-01): ordering check BEFORE weight is counted.
            if (signer <= lastSigner) {
                return ERC1271_INVALID;
            }
            lastSigner = signer;

            uint256 guardianWeight = _guardianWeight(bytes32(0), account, signer);
            // Non-last zero-weight signer REVERTS ZeroWeightSigner (gas-griefing guard).
            if (guardianWeight == 0) {
                _revertZeroWeightSigner();
            }
            totalWeight += guardianWeight;
            if (totalWeight >= threshold) {
                return ERC1271_MAGICVALUE;
            }
        }

        // Process last signature (index sigCount - 1).
        signer = _recoverSigner(sigCount - 1);
        if (signer <= lastSigner) {
            return ERC1271_INVALID;
        }
        uint256 lastWeight = _guardianWeight(bytes32(0), account, signer);
        // Last signer with zero weight returns false (no revert).
        if (lastWeight == 0) {
            return ERC1271_INVALID;
        }
        totalWeight += lastWeight;
        if (totalWeight >= threshold) {
            return ERC1271_MAGICVALUE;
        }

        return ERC1271_INVALID;
    }

    /// @notice Real adapter weight lookup (guardian[signer][account].weight), envfree read.
    function weightOf(address account, address signer) external view returns (uint256) {
        return _guardianWeight(bytes32(0), account, signer);
    }

    /// @notice Real adapter threshold (weightedStorage[account].threshold), envfree read.
    function thresholdOf(address account) external view returns (uint256) {
        return weightedStorage[account].threshold;
    }
}
