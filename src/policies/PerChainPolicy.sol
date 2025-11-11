pragma solidity ^0.8.0;

struct ChainPolicyArgs {
    uint256[] chainIds;
    bytes24[] callAddrAndSelector;
}

struct ChainPolicyConfig {
    bool check;
    bytes24[] callAddrAndSelector;
}
import {PolicyBase} from "src/base/PolicyBase.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC7579Account} from "src/interfaces/IERC7579Account.sol";
import {IAccountExecute} from "account-abstraction/interfaces/IAccountExecute.sol";
import {ExecMode, CallType, ExecType} from "src/types/Types.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";
import {CALLTYPE_SINGLE, CALLTYPE_BATCH} from "src/types/Constants.sol";

contract PerChainPolicy is PolicyBase {
    error CallViolatesParamRule();
    error NotSupported();
    error AlreadyTaken();
    error InvalidId();
    mapping(bytes32 id => mapping(address account => ChainPolicyConfig)) public config;
    mapping(bytes32 id => mapping(address account => bool)) public configured;
    mapping(address account => uint256) public usedIds;

    function isInitialized(address account) external view override returns (bool) {
        return usedIds[account] > 0;
    }

    function _policyOninstall(bytes32 id, bytes calldata data) internal override {
        if(configured[id][msg.sender]) {
            revert AlreadyTaken();
        }
        configured[id][msg.sender] = true;
        usedIds[msg.sender]++;
        bytes1 mode = data[0];
        if (mode == bytes1(0)) {
            // check only on given chains
            ChainPolicyArgs calldata args;
            assembly {
                args := add(data.offset, 1)
            }
            _installMode0(id, args);
        } else if (mode == bytes1(0x01)) {
            // check on all other chains than given chains
            ChainPolicyArgs calldata args;
            assembly {
                args := add(data.offset, 1)
            }
            _installMode1(id, args);
        } else {
            revert NotSupported();
        }
    }

    function _policyOnUninstall(bytes32 id, bytes calldata) internal override {
        if(!configured[id][msg.sender]) {
            revert InvalidId();
        }
        usedIds[msg.sender]--;
        delete config[id][msg.sender];
    }

    function _installMode0(bytes32 id, ChainPolicyArgs calldata args) internal {
        for (uint256 i = 0; i < args.chainIds.length; i++) {
            if (args.chainIds[i] == block.chainid) {
                config[id][msg.sender] = ChainPolicyConfig({check: true, callAddrAndSelector: args.callAddrAndSelector});
                return;
            }
        }
        // if not found, don't check
    }

    function _installMode1(bytes32 id, ChainPolicyArgs calldata args) internal {
        for (uint256 i = 0; i < args.chainIds.length; i++) {
            if (args.chainIds[i] == block.chainid) {
                // if found, don't check
                return;
            }
        }
        config[id][msg.sender] = ChainPolicyConfig({check: true, callAddrAndSelector: args.callAddrAndSelector});
    }

    function checkUserOpPolicy(bytes32 id, PackedUserOperation calldata userOp)
        external
        payable
        override
        returns (uint256)
    {
        ChainPolicyConfig storage thisConfig = config[id][msg.sender];
        if (thisConfig.check) {
            _checkCallData(userOp.callData, thisConfig.callAddrAndSelector);
        }
        return 0;
    }

    function checkSignaturePolicy(bytes32 id, address, bytes32, bytes calldata)
        external
        view
        override
        returns (uint256)
    {
        ChainPolicyConfig memory thisConfig = config[id][msg.sender];
        if (thisConfig.check) {
            // this is not allowed for this id
            return 1;
        }
        return 0;
    }

    function _checkCallData(bytes calldata callData, bytes24[] storage callAddrAndSelector) internal {
        if (bytes4(callData[0:4]) == IAccountExecute.executeUserOp.selector) {
            callData = callData[4:];
        }
        require(bytes4(callData[0:4]) == IERC7579Account.execute.selector);
        bytes32 mode = bytes32(callData[4:36]);
        bytes1 callType = LibERC7579.getCallType(mode);
        bytes calldata executionCallData = callData[36:];
        if (callType == CALLTYPE_SINGLE) {
            (address target, uint256 value, bytes calldata cd) = LibERC7579.decodeSingle(executionCallData);
            bool permissionPass = _checkPermission(target, cd, value, callAddrAndSelector);
            if (!permissionPass) {
                revert CallViolatesParamRule();
            }
        } else if (callType == CALLTYPE_BATCH) {
            bytes32[] calldata pointers = LibERC7579.decodeBatch(executionCallData);
            for (uint256 i = 0; i < pointers.length; i++) {
                (address target, uint256 value, bytes calldata cd) = LibERC7579.getExecution(pointers, i);
                bool permissionPass = _checkPermission(target, cd, value, callAddrAndSelector);
                if (!permissionPass) {
                    revert CallViolatesParamRule();
                }
            }
        } else {
            revert NotSupported();
        }
    }

    function _checkPermission(address target, bytes calldata data, uint256, bytes24[] storage allowed)
        internal
        returns (bool)
    {
        for (uint256 i = 0; i < allowed.length; i++) {
            address t = address(bytes20(allowed[i]));
            bytes4 selector = bytes4(uint32(uint192(allowed[i])));
            if (target == t && bytes4(data[0:4]) == selector) {
                return true;
            }
        }
        return false;
    }
}
