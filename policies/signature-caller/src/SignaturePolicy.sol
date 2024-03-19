pragma solidity ^0.8.0;

import "kernel/sdk/moduleBase/PolicyBase.sol";

enum Status {
    NA,
    Live,
    Deprecated
}

contract SignaturePolicy is PolicyBase {
    mapping(address => uint256) public usedIds;
    mapping(bytes32 id => mapping(address => Status)) public status;
    mapping(bytes32 id => mapping(address caller => mapping(address wallet => bool))) public allowedCaller;

    function isInitialized(address wallet) external view override returns (bool) {
        return usedIds[wallet] > 0;
    }

    function checkUserOpPolicy(bytes32 id, PackedUserOperation calldata userOp)
        external
        payable
        override
        returns (uint256)
    {
        require(status[id][msg.sender] == Status.Live);
        return 0; // always pass
    }

    function checkSignaturePolicy(bytes32 id, address sender, bytes32 hash, bytes calldata sig)
        external
        view
        override
        returns (uint256)
    {
        require(status[id][msg.sender] == Status.Live);
        if (allowedCaller[id][sender][msg.sender]) {
            return 0;
        }
        return 1;
    }

    function _policyOninstall(bytes32 id, bytes calldata _data) internal override {
        require(status[id][msg.sender] == Status.NA);
        address[] memory callers = abi.decode(_data, (address[]));
        for (uint256 i = 0; i < callers.length; i++) {
            allowedCaller[id][callers[i]][msg.sender] = true;
        }
        status[id][msg.sender] = Status.Live;
        usedIds[msg.sender]++;
    }

    function _policyOnUninstall(bytes32 id, bytes calldata _data) internal override {
        require(status[id][msg.sender] == Status.Live);
        status[id][msg.sender] = Status.Deprecated;
        usedIds[msg.sender]--;
    }
}
