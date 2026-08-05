pragma solidity ^0.8.0;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
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
        (uint256 verificationGasLimit, uint256 callGasLimit) =
            (uint128(bytes16(userOp.accountGasLimits)), uint128(uint256(userOp.accountGasLimits)));
        uint256 maxFeePerGas = uint128(uint256(userOp.gasFees));
        uint256 maxAmount = (userOp.preVerificationGas + verificationGasLimit + callGasLimit) * maxFeePerGas;
        if (gasPolicyConfig[id][msg.sender].enforcePaymaster) {
            address allowedPaymaster = gasPolicyConfig[id][msg.sender].allowedPaymaster;
            if (
                allowedPaymaster != address(0)
                    && (userOp.paymasterAndData.length < 20
                        || address(bytes20(userOp.paymasterAndData[0:20])) != allowedPaymaster)
            ) {
                return SIG_VALIDATION_FAILED_UINT;
            }
        }
        if (maxAmount > gasPolicyConfig[id][msg.sender].allowed) {
            return SIG_VALIDATION_FAILED_UINT;
        }
        gasPolicyConfig[id][msg.sender].allowed = uint128(gasPolicyConfig[id][msg.sender].allowed - maxAmount);
        return SIG_VALIDATION_SUCCESS_UINT;
    }

    function checkSignaturePolicy(bytes32 id, address, bytes32, bytes calldata)
        external
        view
        override
        returns (uint256)
    {
        require(status[id][msg.sender] == Status.Live, PolicyNotLive());
        return SIG_VALIDATION_SUCCESS_UINT;
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
