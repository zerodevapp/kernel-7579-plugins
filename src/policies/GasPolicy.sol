pragma solidity ^0.8.0;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {UserOperationLib} from "account-abstraction/core/UserOperationLib.sol";
import {PolicyBase} from "src/base/PolicyBase.sol";
import {SIG_VALIDATION_SUCCESS_UINT, SIG_VALIDATION_FAILED_UINT} from "src/types/Constants.sol";

enum Status {
    NA,
    Live,
    Deprecated
}

struct GasPolicyConfig {
    uint128 allowed;
    bool enforcePaymaster;
    address allowedPaymaster;
}

/**
 * @title GasPolicy
 * @notice Caps the cumulative gas cost a permission may spend, optionally restricted to a paymaster.
 * @dev Per-(id, wallet) budget decremented on each user operation.
 */
contract GasPolicy is PolicyBase {
    error PolicyNotLive();
    error PolicyAlreadyInstalled();

    mapping(bytes32 id => mapping(address => Status)) public status;
    mapping(bytes32 id => mapping(address => GasPolicyConfig)) public gasPolicyConfig;

    function checkUserOpPolicy(bytes32 id, PackedUserOperation calldata userOp)
        external
        payable
        override
        returns (uint256)
    {
        require(status[id][msg.sender] == Status.Live, PolicyNotLive());
        uint256 paymasterVerificationGasLimit;
        uint256 paymasterPostOpGasLimit;
        address paymaster;

        bytes calldata paymasterAndData = userOp.paymasterAndData;
        if (paymasterAndData.length != 0) {
            if (paymasterAndData.length < UserOperationLib.PAYMASTER_DATA_OFFSET) {
                return SIG_VALIDATION_FAILED_UINT;
            }
            (paymaster, paymasterVerificationGasLimit, paymasterPostOpGasLimit) =
                UserOperationLib.unpackPaymasterStaticFields(paymasterAndData);
            if (paymaster == address(0)) return SIG_VALIDATION_FAILED_UINT;
        }

        GasPolicyConfig storage config = gasPolicyConfig[id][msg.sender];
        if (config.enforcePaymaster) {
            if (paymaster == address(0)) return SIG_VALIDATION_FAILED_UINT;
            if (config.allowedPaymaster != address(0) && paymaster != config.allowedPaymaster) {
                return SIG_VALIDATION_FAILED_UINT;
            }
        }

        (uint256 verificationGasLimit, uint256 callGasLimit) = UserOperationLib.unpackUints(userOp.accountGasLimits);
        uint256 maxFeePerGas = UserOperationLib.unpackMaxFeePerGas(userOp);
        uint256 maxAmount =
            (userOp.preVerificationGas
                    + verificationGasLimit
                    + callGasLimit
                    + paymasterVerificationGasLimit
                    + paymasterPostOpGasLimit) * maxFeePerGas;
        if (maxAmount > config.allowed) {
            return SIG_VALIDATION_FAILED_UINT;
        }
        config.allowed = uint128(config.allowed - maxAmount);
        return SIG_VALIDATION_SUCCESS_UINT;
    }

    function checkSignaturePolicy(bytes32 id, address, bytes32, bytes calldata)
        external
        view
        override
        returns (uint256)
    {
        require(status[id][msg.sender] == Status.Live, PolicyNotLive());
        return SIG_VALIDATION_FAILED_UINT;
    }

    function _policyOninstall(bytes32 id, bytes calldata _data) internal override {
        require(status[id][msg.sender] == Status.NA, PolicyAlreadyInstalled());
        (uint128 allowed, bool enforcePaymaster, address allowedPaymaster) = abi.decode(_data, (uint128, bool, address));
        gasPolicyConfig[id][msg.sender] = GasPolicyConfig(allowed, enforcePaymaster, allowedPaymaster);
        status[id][msg.sender] = Status.Live;
    }

    function _policyOnUninstall(bytes32 id, bytes calldata) internal override {
        require(status[id][msg.sender] == Status.Live, PolicyNotLive());
        status[id][msg.sender] = Status.Deprecated;
    }
}
