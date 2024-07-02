pragma solidity ^0.8.0;

import "kernel/sdk/moduleBase/PolicyBase.sol";
import "kernel/utils/ExecLib.sol";
import {IERC7579Account} from "kernel/interfaces/IERC7579Account.sol";

struct Permission {
    CallType callType; // calltype can be CALLTYPE_SINGLE/CALLTYPE_DELEGATECALL
    address target;
    bytes4 selector;
    uint256 valueLimit;
    ParamRule[] rules;
}

struct ParamRule {
    ParamCondition condition;
    uint64 offset;
    bytes32[] params;
}

enum ParamCondition {
    EQUAL,
    GREATER_THAN,
    LESS_THAN,
    GREATER_THAN_OR_EQUAL,
    LESS_THAN_OR_EQUAL,
    NOT_EQUAL,
    ONE_OF
}

enum Status {
    NA,
    Live,
    Deprecated
}

contract CallPolicy is PolicyBase {
    error InvalidCallType();
    error CallViolatesParamRule();
    error CallViolatesValueRule();

    mapping(address => uint256) public usedIds;
    mapping(bytes32 id => mapping(address => Status)) public status;
    mapping(bytes32 id => mapping(bytes32 permissionHash => mapping(address => bytes))) public encodedPermissions;

    function isInitialized(address wallet) external view override returns (bool) {
        return usedIds[wallet] > 0;
    }

    function checkUserOpPolicy(bytes32 id, PackedUserOperation calldata userOp)
        external
        payable
        override
        returns (uint256)
    {
        require(bytes4(userOp.callData[0:4]) == IERC7579Account.execute.selector);
        ExecMode mode = ExecMode.wrap(bytes32(userOp.callData[4:36]));
        (CallType callType, ExecType execType,,) = ExecLib.decode(mode);
        bytes calldata executionCallData = userOp.callData; // Cache calldata here
        assembly {
            executionCallData.offset :=
                add(add(executionCallData.offset, 0x24), calldataload(add(executionCallData.offset, 0x24)))
            executionCallData.length := calldataload(sub(executionCallData.offset, 0x20))
        }
        if (callType == CALLTYPE_SINGLE) {
            (address target, uint256 value, bytes calldata callData) = ExecLib.decodeSingle(executionCallData);
            bool permissionPass = _checkPermission(msg.sender, id, CALLTYPE_SINGLE, target, callData, value);
            if (!permissionPass) {
                revert CallViolatesParamRule();
            }
        } else if (callType == CALLTYPE_BATCH) {
            Execution[] calldata exec = ExecLib.decodeBatch(executionCallData);
            for (uint256 i = 0; i < exec.length; i++) {
                bool permissionPass =
                    _checkPermission(msg.sender, id, CALLTYPE_SINGLE, exec[i].target, exec[i].callData, exec[i].value);
                if (!permissionPass) {
                    revert CallViolatesParamRule();
                }
            }
        } else if (callType == CALLTYPE_DELEGATECALL) {
            (address target, uint256 value, bytes calldata callData) = ExecLib.decodeSingle(executionCallData);
            bool permissionPass = _checkPermission(msg.sender, id, CALLTYPE_DELEGATECALL, target, callData, value);
            if (!permissionPass) {
                revert CallViolatesParamRule();
            }
        } else {
            revert InvalidCallType();
        }
    }

    function _checkPermission(
        address wallet,
        bytes32 id,
        CallType callType,
        address target,
        bytes calldata data,
        uint256 value
    ) internal returns (bool) {
        bytes4 _data = data.length == 0 ? bytes4(0x0) : bytes4(data[0:4]);
        bytes32 permissionHash = keccak256(abi.encodePacked(callType, target, _data));
        bytes memory encodedPermission = encodedPermissions[id][permissionHash][wallet];

        if (encodedPermission.length == 0) {
            bytes32 permissionHashWithZeroAddress = keccak256(abi.encodePacked(callType, address(0), _data));
            encodedPermission = encodedPermissions[id][permissionHashWithZeroAddress][wallet];
        }
        (uint256 allowedValue, ParamRule[] memory rules) = abi.decode(encodedPermission, (uint256, ParamRule[]));

        if (value > allowedValue) {
            revert CallViolatesValueRule();
        }
        for (uint256 i = 0; i < rules.length; i++) {
            ParamRule memory rule = rules[i];
            bytes32 param = bytes32(data[4 + rule.offset:4 + rule.offset + 32]);
            // only ONE_OF condition can have multiple params
            if (rule.condition == ParamCondition.EQUAL && param != rule.params[0]) {
                return false;
            } else if (rule.condition == ParamCondition.GREATER_THAN && param <= rule.params[0]) {
                return false;
            } else if (rule.condition == ParamCondition.LESS_THAN && param >= rule.params[0]) {
                return false;
            } else if (rule.condition == ParamCondition.GREATER_THAN_OR_EQUAL && param < rule.params[0]) {
                return false;
            } else if (rule.condition == ParamCondition.LESS_THAN_OR_EQUAL && param > rule.params[0]) {
                return false;
            } else if (rule.condition == ParamCondition.NOT_EQUAL && param == rule.params[0]) {
                return false;
            } else if (rule.condition == ParamCondition.ONE_OF) {
                bool oneOfStatus = false;
                for (uint256 j = 0; j < rule.params.length; j++) {
                    if (param == rule.params[j]) {
                        oneOfStatus = true;
                        break;
                    }
                }
                if (!oneOfStatus) {
                    return false;
                }
            }
        }
        return true;
    }

    function checkSignaturePolicy(bytes32 id, address sender, bytes32 hash, bytes calldata sig)
        external
        view
        override
        returns (uint256)
    {
        require(status[id][msg.sender] == Status.Live);
        return 0;
    }

    function _parsePermission(bytes calldata _sig) internal pure returns (Permission[] calldata permissions) {
        assembly {
            permissions.offset := add(add(_sig.offset, 32), calldataload(_sig.offset))
            permissions.length := calldataload(sub(permissions.offset, 32))
        }
    }

    function _policyOninstall(bytes32 id, bytes calldata _data) internal override {
        require(status[id][msg.sender] == Status.NA);
        Permission[] calldata permissions = _parsePermission(_data);
        for (uint256 i = 0; i < permissions.length; i++) {
            // check if the permissionHash is unique
            bytes32 permissionHash =
                keccak256(abi.encodePacked(permissions[i].callType, permissions[i].target, permissions[i].selector));
            require(encodedPermissions[id][permissionHash][msg.sender].length == 0, "duplicate permissionHash");

            // check if the params length is correct
            for (uint256 j = 0; j < permissions[i].rules.length; j++) {
                if (permissions[i].rules[j].condition != ParamCondition.ONE_OF) {
                    require(permissions[i].rules[j].params.length == 1, "only OneOf condition can have multiple params");
                }
            }

            encodedPermissions[id][permissionHash][msg.sender] =
                abi.encode(permissions[i].valueLimit, permissions[i].rules);
        }
        status[id][msg.sender] = Status.Live;
        usedIds[msg.sender]++;
    }

    function _policyOnUninstall(bytes32 id, bytes calldata _data) internal override {
        require(status[id][msg.sender] == Status.Live);
        //delete encodedPermissions[id][msg.sender];
        status[id][msg.sender] = Status.Deprecated;
        usedIds[msg.sender]--;
    }
}
