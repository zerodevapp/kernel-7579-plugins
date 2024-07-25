pragma solidity ^0.8.0;

import "kernel/sdk/moduleBase/SignerBase.sol";

contract AnySigner is SignerBase {
    mapping(address => uint256) public usedIds;

    function isInitialized(address wallet) external view override returns (bool) {
        return usedIds[wallet] > 0;
    }

    function checkUserOpSignature(bytes32 id, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        override
        returns (uint256)
    {
        return 0;
    }

    function checkSignature(bytes32 id, address sender, bytes32 hash, bytes calldata sig)
        external
        view
        override
        returns (bytes4)
    {
        return 0x1626ba7e;
    }

    function _signerOninstall(bytes32 id, bytes calldata _data) internal override {
        usedIds[msg.sender]++;
    }

    function _signerOnUninstall(bytes32 id, bytes calldata) internal override {
        require(usedIds[msg.sender] > 0);
        usedIds[msg.sender]--;
    }
}
