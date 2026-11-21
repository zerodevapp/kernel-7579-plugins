// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ECDSA} from "solady/utils/ECDSA.sol";

/// @title WeightedThresholdBase
/// @author taek <leekt216@gmail.com>
/// @notice Single, shared copy of the weighted-threshold signature-aggregation logic used by
///         both WeightedECDSASigner and WeightedECDSAValidator. Ported verbatim from the
///         (correct, EC-01-fixed) logic that previously lived in WeightedECDSASigner.
/// @dev    Weight lookups are indirected through `_guardianWeight` so each adapter can plug in
///         its own storage layout (id-keyed for the signer, single-config for the validator)
///         without duplicating the aggregation invariants.
abstract contract WeightedThresholdBase {
    // ZeroWeightSigner() / SignersNotSorted() are declared by each concrete adapter so that
    // `<Adapter>.ZeroWeightSigner.selector` resolves in that adapter's test suite (Solidity does
    // not expose inherited errors via the derived contract name). The base reverts through the
    // hooks below; both hooks MUST revert (the base relies on that to abort aggregation).

    /// @dev Reverts the adapter's ZeroWeightSigner() error. MUST revert.
    function _revertZeroWeightSigner() internal pure virtual;

    /// @dev Reverts the adapter's SignersNotSorted() error. MUST revert.
    function _revertSignersNotSorted() internal pure virtual;

    /// @notice Returns the weight of `signer` for the given config/account.
    /// @param cfg Adapter-specific config key (permission id for the signer, bytes32(0) for the validator).
    /// @param account The smart account the guardian set belongs to.
    /// @param signer The recovered signer whose weight is requested.
    /// @return weight The guardian's weight (0 if not a guardian).
    function _guardianWeight(bytes32 cfg, address account, address signer) internal view virtual returns (uint256);

    /// @notice Verify a plain (ERC-1271 style) weighted-threshold signature over a single hash.
    /// @dev EXACT mirror of the original WeightedECDSASigner._validateSignature. Signers must be in
    ///      strictly ASCENDING order; a non-last zero-weight signer REVERTS ZeroWeightSigner; a last
    ///      zero-weight signer returns false. Threshold reached via `>=`.
    /// @return ok True iff the accumulated distinct-signer weight reaches `threshold`.
    function _verifySorted(bytes32 cfg, address account, bytes32 hash, bytes calldata sig, uint256 threshold)
        internal
        view
        returns (bool ok)
    {
        if (threshold == 0) {
            return false;
        }

        uint256 sigCount = sig.length / 65;
        if (sigCount == 0) {
            return false;
        }

        uint256 totalWeight = 0;
        address signer;
        address lastSigner = address(0);

        // Process all signatures except the last one
        for (uint256 i = 0; i < sigCount - 1; i++) {
            signer = ECDSA.tryRecoverCalldata(hash, sig[i * 65:(i + 1) * 65]);

            // Enforce sorted order to prevent signature reuse (EC-01: ordering check BEFORE counting)
            if (signer <= lastSigner) {
                return false;
            }
            lastSigner = signer;

            uint256 guardianWeight = _guardianWeight(cfg, account, signer);
            // Revert if non-last signer has zero weight (prevents gas griefing)
            if (guardianWeight == 0) {
                _revertZeroWeightSigner();
            }
            totalWeight += guardianWeight;
            if (totalWeight >= threshold) {
                return true;
            }
        }

        // Process last signature
        signer = ECDSA.tryRecoverCalldata(hash, sig[sig.length - 65:]);
        if (signer <= lastSigner) {
            return false;
        }
        uint256 lastWeight = _guardianWeight(cfg, account, signer);
        // If last signer has zero weight, return false (don't revert)
        if (lastWeight == 0) {
            return false;
        }
        totalWeight += lastWeight;
        if (totalWeight >= threshold) {
            return true;
        }

        return false;
    }

    /// @notice Verify a split UserOp weighted-threshold signature.
    /// @dev EXACT mirror of the original WeightedECDSASigner._validateUserOpSignature.
    ///      The first N-1 signatures sign `proposalHash` in strictly ASCENDING order (a non-last
    ///      zero-weight signer REVERTS ZeroWeightSigner). The LAST signature signs `finalHash` to
    ///      bind the full UserOp; a last zero-weight signer returns false (no revert). An in-memory
    ///      de-dup ensures the final signer's weight is counted at most once. Threshold via `>=`.
    /// @return ok True iff the accumulated distinct-signer weight reaches `threshold`.
    function _verifyUserOp(
        bytes32 cfg,
        address account,
        bytes32 proposalHash,
        bytes32 finalHash,
        bytes calldata sig,
        uint256 threshold
    ) internal view returns (bool ok) {
        if (threshold == 0) {
            return false;
        }

        if (sig.length % 65 != 0) {
            return false;
        }

        uint256 sigCount = sig.length / 65;
        if (sigCount == 0) {
            return false;
        }

        uint256 totalWeight = 0;
        address signer;
        address lastSigner = address(0);

        // Track proposalHash signers to prevent double-counting with the finalHash signer
        address[] memory proposalSigners = new address[](sigCount - 1);

        // Process all signatures except the last one (they sign proposalHash)
        // Signers must be in strictly ascending order to prevent reuse
        // NOTE: No early return - must always verify the finalHash signature
        for (uint256 i = 0; i < sigCount - 1; i++) {
            signer = ECDSA.tryRecoverCalldata(proposalHash, sig[i * 65:(i + 1) * 65]);

            // Enforce sorted order to prevent signature reuse (EC-01: ordering check BEFORE counting)
            if (signer <= lastSigner) {
                _revertSignersNotSorted();
            }
            lastSigner = signer;
            proposalSigners[i] = signer;

            uint256 guardianWeight = _guardianWeight(cfg, account, signer);
            // Revert if non-last signer has zero weight (prevents gas griefing)
            if (guardianWeight == 0) {
                _revertZeroWeightSigner();
            }
            totalWeight += guardianWeight;
            // No early return here - must verify finalHash signature
        }

        // Last signature MUST verify finalHash to bind the full userOp
        signer = ECDSA.tryRecoverCalldata(finalHash, sig[sig.length - 65:]);

        uint256 lastWeight = _guardianWeight(cfg, account, signer);
        // If last signer has zero weight, return false (don't revert)
        if (lastWeight == 0) {
            return false;
        }

        // Check if finalHash signer already signed proposalHash (prevent double-counting)
        bool alreadySigned = false;
        for (uint256 i = 0; i < proposalSigners.length; i++) {
            if (proposalSigners[i] == signer) {
                alreadySigned = true;
                break;
            }
        }

        // Only add weight if signer hasn't already contributed via proposalHash
        if (!alreadySigned) {
            totalWeight += lastWeight;
        }

        return totalWeight >= threshold;
    }
}
