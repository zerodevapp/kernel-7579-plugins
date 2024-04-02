// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "kernel/sdk/moduleBase/PolicyBase.sol";

contract SudoPolicy is PolicyBase {
    // TODO: how should we handle this?
    function isInitialized(address wallet) external view override returns (bool) {
        return false;
    }

    function checkUserOpPolicy(bytes32 id, PackedUserOperation calldata userOp)
        external
        payable
        override
        returns (uint256)
    {
        return 0;
    }

    function checkSignaturePolicy(bytes32 id, address sender, bytes32 hash, bytes calldata sig)
        external
        view
        override
        returns (uint256)
    {
        return 0;
    }

    function _policyOninstall(bytes32 id, bytes calldata _data) internal override {}

    function _policyOnUninstall(bytes32 id, bytes calldata _data) internal override {}
}
