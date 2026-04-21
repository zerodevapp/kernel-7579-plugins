// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAccount} from "account-abstraction/interfaces/IAccount.sol";
import {IAccountExecute} from "account-abstraction/interfaces/IAccountExecute.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";
import {TimelockPolicy} from "../../src/policies/TimelockPolicy.sol";

/// @title MockTimelockAccount
/// @notice Minimal ERC-4337 + ERC-7579 account that delegates validation to TimelockPolicy.
///         Implements execute() (ERC-7579 single call via Solady's LibERC7579) and
///         executeUserOp() (ERC-4337) so no-op detection tests exercise realistic execution paths.
contract MockTimelockAccount is IAccount, IAccountExecute {
    using LibERC7579 for bytes32;
    using LibERC7579 for bytes;

    IEntryPoint public immutable entryPoint;
    TimelockPolicy public immutable policy;
    bytes32 public immutable policyId;

    uint256 public value;

    error UnsupportedCallType();

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

    /// @notice ERC-7579 execute — only supports single call (CALLTYPE_SINGLE).
    ///         Uses Solady's LibERC7579.decodeSingle() for the packed format.
    function execute(bytes32 mode, bytes calldata executionCalldata) external payable {
        require(msg.sender == address(entryPoint) || msg.sender == address(this), "only entrypoint or self");

        bytes1 callType = mode.getCallType();
        if (callType != LibERC7579.CALLTYPE_SINGLE) revert UnsupportedCallType();

        // Empty executionCalldata = true no-op (nothing to decode or call)
        if (executionCalldata.length == 0) return;

        (address target, uint256 val, bytes calldata data) = executionCalldata.decodeSingle();

        (bool ok, bytes memory ret) = target.call{value: val}(data);
        if (!ok) {
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }
    }

    /// @notice ERC-4337 executeUserOp — EntryPoint calls this when callData starts with executeUserOp selector.
    ///         Extracts inner calldata from userOp.callData[4:] and self-calls.
    function executeUserOp(PackedUserOperation calldata userOp, bytes32) external {
        require(msg.sender == address(entryPoint), "only entrypoint");

        bytes calldata innerCalldata = userOp.callData[4:];
        if (innerCalldata.length == 0) return; // executeUserOp with no inner data = no-op

        (bool ok, bytes memory ret) = address(this).call(innerCalldata);
        if (!ok) {
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }
    }

    function setValue(uint256 _value) external {
        value = _value;
    }

    receive() external payable {}
}
