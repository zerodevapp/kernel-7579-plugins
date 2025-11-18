pragma solidity ^0.8.0;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IStatelessValidatorWithSender, IModule} from "src/interfaces/IERC7579Modules.sol";
import {PolicyBase} from "src/base/PolicyBase.sol";

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
} from "src/types/Constants.sol";

contract SignaturePolicy is PolicyBase, IStatelessValidatorWithSender {
    mapping(bytes32 id => mapping(address => Status)) public status;
    mapping(bytes32 id => mapping(address caller => mapping(address wallet => bool))) public allowedCaller;

    function isModuleType(uint256 typeID) external pure override(IModule, PolicyBase) returns (bool) {
        return typeID == MODULE_TYPE_POLICY || typeID == MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER;
    }

    function checkUserOpPolicy(bytes32 id, PackedUserOperation calldata userOp)
        external
        payable
        override
        returns (uint256)
    {
        return _validateUserOpPolicy(id, msg.sender);
    }

    function checkSignaturePolicy(bytes32 id, address sender, bytes32 hash, bytes calldata sig)
        external
        view
        override
        returns (uint256)
    {
        return _validateSignaturePolicy(id, sender, msg.sender);
    }

    // ==================== Internal Shared Logic ====================

    /**
     * @notice Internal function to validate user operation policy
     * @dev Shared logic for both installed and stateless validator modes
     */
    function _validateUserOpPolicy(bytes32 id, address account) internal view returns (uint256) {
        if (status[id][account] != Status.Live) {
            return SIG_VALIDATION_FAILED_UINT;
        }
        return SIG_VALIDATION_SUCCESS_UINT; // always pass if policy is live
    }

    /**
     * @notice Internal function to validate signature policy
     * @dev Shared logic for both installed and stateless validator modes
     */
    function _validateSignaturePolicy(bytes32 id, address sender, address account) internal view returns (uint256) {
        if (status[id][account] != Status.Live) {
            return 1;
        }
        if (allowedCaller[id][sender][account]) {
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
    }

    function _policyOnUninstall(bytes32 id, bytes calldata _data) internal override {
        require(status[id][msg.sender] == Status.Live);
        status[id][msg.sender] = Status.Deprecated;
    }

    function validateSignatureWithDataWithSender(address sender, bytes32, bytes calldata, bytes calldata data)
        external
        pure
        override(IStatelessValidatorWithSender)
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
