pragma solidity ^0.8.0;

import "kernel_v3/sdk/moduleBase/PolicyBase.sol";
import {ValidAfter, ValidUntil, packValidationData} from "kernel/types/Types.sol";

enum Status {
    NA,
    Live,
    Deprecated
}

struct TimestampPolicyConfig {
    ValidAfter validAfter;
    ValidUntil validUntil;
}

contract TimestampPolicy is PolicyBase {
    mapping(address => uint256) public usedIds;
    mapping(bytes32 id => mapping(address => Status)) public status;
    mapping(bytes32 id => mapping(address => TimestampPolicyConfig)) public timestampPolicyConfig;

    function isInitialized(address wallet) external view override returns (bool) {
        return usedIds[wallet] > 0;
    }

    function checkUserOpPolicy(bytes32 id, PackedUserOperation calldata)
        external
        payable
        override
        returns (uint256)
    {
        require(status[id][msg.sender] == Status.Live);
        TimestampPolicyConfig memory config = timestampPolicyConfig[id][msg.sender];
        return packValidationData(config.validAfter, config.validUntil);
    }

    function checkSignaturePolicy(bytes32 id, address, bytes32, bytes calldata)
        external
        view
        override
        returns (uint256)
    {
        require(status[id][msg.sender] == Status.Live);
        return 0;
    }

    function _policyOninstall(bytes32 id, bytes calldata _data) internal override {
        require(status[id][msg.sender] == Status.NA);
        (ValidAfter validAfter, ValidUntil validUntil) = abi.decode(_data, (ValidAfter, ValidUntil));
        timestampPolicyConfig[id][msg.sender] = TimestampPolicyConfig(validAfter, validUntil);
        status[id][msg.sender] = Status.Live;
        usedIds[msg.sender]++;
    }

    function _policyOnUninstall(bytes32 id, bytes calldata) internal override {
        require(status[id][msg.sender] == Status.Live);
        status[id][msg.sender] = Status.Deprecated;
        usedIds[msg.sender]--;
    }
}
