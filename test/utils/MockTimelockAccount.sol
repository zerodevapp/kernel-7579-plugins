// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAccount} from "account-abstraction/interfaces/IAccount.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {TimelockPolicy} from "../../src/policies/TimelockPolicy.sol";

/// @title MockTimelockAccount
/// @notice Minimal IAccount that delegates validation to TimelockPolicy.
///         Used for integration testing with the real EntryPoint.
contract MockTimelockAccount is IAccount {
    IEntryPoint public immutable entryPoint;
    TimelockPolicy public immutable policy;
    bytes32 public immutable policyId;

    uint256 public value;

    constructor(IEntryPoint _entryPoint, TimelockPolicy _policy, bytes32 _policyId) {
        entryPoint = _entryPoint;
        policy = _policy;
        policyId = _policyId;
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32, uint256 missingAccountFunds)
        external
        returns (uint256 validationData)
    {
        require(msg.sender == address(entryPoint), "only entrypoint");

        if (missingAccountFunds > 0) {
            (bool ok,) = payable(msg.sender).call{value: missingAccountFunds}("");
            require(ok);
        }

        return policy.checkUserOpPolicy(policyId, userOp);
    }

    function setValue(uint256 _value) external {
        value = _value;
    }

    receive() external payable {}
}
