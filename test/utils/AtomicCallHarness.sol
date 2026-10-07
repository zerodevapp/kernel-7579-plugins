// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Minimal account stand-in that executes a sequence of calls in one transaction.
/// @dev Timelock validation uses EIP-1153 transient storage, so validation and proposal
///      creation must be nested under one outer call just as they are under EntryPoint.handleOps.
contract AtomicCallHarness {
    struct Call {
        address target;
        bytes data;
    }

    function execute(Call[] calldata calls) external returns (bool[] memory successes, bytes[] memory returnData) {
        uint256 length = calls.length;
        successes = new bool[](length);
        returnData = new bytes[](length);

        for (uint256 i; i < length; ++i) {
            (successes[i], returnData[i]) = calls[i].target.call(calls[i].data);
        }
    }
}
