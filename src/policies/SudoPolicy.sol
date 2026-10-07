pragma solidity ^0.8.0;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {PolicyBase} from "src/base/PolicyBase.sol";
import {SIG_VALIDATION_SUCCESS_UINT} from "src/types/Constants.sol";

/**
 * @title SudoPolicy
 * @notice A policy that unconditionally approves every user operation and signature.
 * @dev Grants unrestricted permission — pair with other policies only when a permission
 *      genuinely needs no additional constraints.
 */
contract SudoPolicy is PolicyBase {
    function checkUserOpPolicy(bytes32, PackedUserOperation calldata) external payable override returns (uint256) {
        return SIG_VALIDATION_SUCCESS_UINT;
    }

    function checkSignaturePolicy(bytes32, address, bytes32, bytes calldata) external view override returns (uint256) {
        return SIG_VALIDATION_SUCCESS_UINT;
    }

    function _policyOninstall(bytes32, bytes calldata) internal override {}

    function _policyOnUninstall(bytes32, bytes calldata) internal override {}
}
