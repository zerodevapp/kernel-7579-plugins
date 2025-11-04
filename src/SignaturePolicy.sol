pragma solidity ^0.8.0;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

enum Status {
    NA,
    Live,
    Deprecated
}

import {
    SIG_VALIDATION_SUCCESS_UINT,
    SIG_VALIDATION_FAILED_UINT,
    MODULE_TYPE_POLICY,
    MODULE_TYPE_STATELESS_VALIDATOR,
    MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER,
    ERC1271_MAGICVALUE,
    ERC1271_INVALID
} from "./types/Constants.sol";

contract SignaturePolicy {
    mapping(address => uint256) public usedIds;
    mapping(bytes32 id => mapping(address => Status)) public status;
    mapping(bytes32 id => mapping(address caller => mapping(address wallet => bool))) public allowedCaller;

    function onInstall(bytes calldata data) external payable {
        bytes32 id = bytes32(data[0:32]);
        bytes calldata _data = data[32:];
        _policyOninstall(id, _data);
    }

    function onUninstall(bytes calldata data) external payable {
        bytes32 id = bytes32(data[0:32]);
        bytes calldata _data = data[32:];
        _policyOnUninstall(id, _data);
    }

    function isModuleType(uint256 typeID) external pure returns (bool) {
        return typeID == MODULE_TYPE_POLICY || typeID == MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER;
    }

    function isInitialized(address wallet) external view returns (bool) {
        return usedIds[wallet] > 0;
    }

    function checkUserOpPolicy(bytes32 id, PackedUserOperation calldata userOp) external payable returns (uint256) {
        require(status[id][msg.sender] == Status.Live);
        return 0; // always pass
    }

    function checkSignaturePolicy(bytes32 id, address sender, bytes32 hash, bytes calldata sig)
        external
        view
        returns (uint256)
    {
        require(status[id][msg.sender] == Status.Live);
        if (allowedCaller[id][sender][msg.sender]) {
            return 0;
        }
        return 1;
    }

    function _policyOninstall(bytes32 id, bytes calldata _data) internal {
        require(status[id][msg.sender] == Status.NA);
        address[] memory callers = abi.decode(_data, (address[]));
        for (uint256 i = 0; i < callers.length; i++) {
            allowedCaller[id][callers[i]][msg.sender] = true;
        }
        status[id][msg.sender] = Status.Live;
        usedIds[msg.sender]++;
    }

    function _policyOnUninstall(bytes32 id, bytes calldata _data) internal {
        require(status[id][msg.sender] == Status.Live);
        status[id][msg.sender] = Status.Deprecated;
        usedIds[msg.sender]--;
    }

    function validateSignatureWithDataWithSender(address sender, bytes32, bytes calldata, bytes calldata data)
        external
        view
        returns (bool)
    {
        address[] memory callers = abi.decode(data, (address[]));
        for (uint256 i = 0; i < callers.length; i++) {
            if (callers[i] == sender) {
                return true;
            }
        }
        return false;
    }
}
