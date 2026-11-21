// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Minimal configurable stand-in for EntryPoint v0.9's execution-phase hash getter.
contract MockTimelockEntryPoint {
    bytes32 private currentUserOpHash;

    function setCurrentUserOpHash(bytes32 userOpHash) external {
        currentUserOpHash = userOpHash;
    }

    function getCurrentUserOpHash() external view returns (bytes32) {
        return currentUserOpHash;
    }
}
