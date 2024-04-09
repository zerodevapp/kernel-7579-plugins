// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "kernel/sdk/moduleBase/PolicyBase.sol";

contract SudoPolicy is PolicyBase {
    mapping(address => uint256) public usedIds;

    function isInitialized(address wallet) external view override returns (bool) {
        return usedIds[wallet] > 0;
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

    function _policyOninstall(bytes32 id, bytes calldata _data) internal override {
        usedIds[msg.sender]++;
    }

    function _policyOnUninstall(bytes32 id, bytes calldata _data) internal override {
        usedIds[msg.sender]--;
    }
}
