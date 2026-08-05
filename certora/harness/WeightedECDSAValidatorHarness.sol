// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {WeightedECDSAValidator, VoteStatus, ProposalStatus} from "src/validators/WeightedECDSAValidator.sol";

/// @notice Certora harness for WeightedECDSAValidator.
/// Exposes the internal epoch-namespaced key derivation and read-only accessors so the
/// stale-approval replay property (RP-01) can be stated over concrete storage slots
/// without having to reason about the guardian linked-list construction machinery.
/// @author taek <leekt216@gmail.com>
contract WeightedECDSAValidatorHarness is WeightedECDSAValidator {
    /// @notice Public wrapper over the internal, configVersion-namespaced key.
    function keyOf(address kernel, bytes32 hash) external view returns (bytes32) {
        return _key(kernel, hash);
    }

    /// @notice Raw vote-slot read at an explicit key (epoch already folded into `key`).
    function voteStatusAt(bytes32 key, address g, address kernel) external view returns (VoteStatus) {
        return voteStatus[key][g][kernel].status;
    }

    /// @notice Read the current epoch.
    function version(address kernel) external view returns (uint256) {
        return configVersion[kernel];
    }

    /// @notice Guardian weight lookup for a (guardian, kernel) pair.
    /// A guardian is "current/enabled" for `kernel` iff this is non-zero.
    function weightOf(address g, address kernel) external view returns (uint24) {
        return guardian[g][kernel].weight;
    }

    /// @notice threshold for a kernel (weightedStorage[kernel].threshold).
    function thresholdOf(address kernel) external view returns (uint24) {
        return weightedStorage[kernel].threshold;
    }
}
