pragma solidity ^0.8.0;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {PolicyBase} from "src/base/PolicyBase.sol";
import {SIG_VALIDATION_SUCCESS_UINT, SIG_VALIDATION_FAILED_UINT} from "src/types/Constants.sol";
import {packValidationData, ValidAfter, ValidUntil} from "src/types/Types.sol";

enum Status {
    NA,
    Live,
    Deprecated
}

struct ThrottleConfig {
    uint48 interval;
    uint48 count;
    ValidAfter startAt;
}

/**
 * @title ThrottlePolicy
 * @notice Limits a permission to a fixed budget of `count` user operations, each spaced at least
 *         `interval` apart. The budget does not refill.
 * @dev Each accepted op decrements the remaining count and pushes the next allowed timestamp
 *      forward by `interval`, returned as `validAfter`.
 */
contract ThrottlePolicy is PolicyBase {
    error PolicyNotLive();
    error PolicyAlreadyInstalled();

    mapping(bytes32 id => mapping(address => Status)) public status;
    mapping(bytes32 id => mapping(address kernel => ThrottleConfig)) public throttleConfigs;

    function checkUserOpPolicy(bytes32 id, PackedUserOperation calldata) external payable override returns (uint256) {
        require(status[id][msg.sender] == Status.Live, PolicyNotLive());
        ThrottleConfig memory config = throttleConfigs[id][msg.sender];
        if (config.count == 0) {
            return SIG_VALIDATION_FAILED_UINT;
        }
        uint48 storedStart = ValidAfter.unwrap(config.startAt);
        uint48 anchored = uint48(block.timestamp) > storedStart ? uint48(block.timestamp) : storedStart;
        throttleConfigs[id][msg.sender].count = config.count - 1;
        throttleConfigs[id][msg.sender].startAt = ValidAfter.wrap(anchored + config.interval);
        return packValidationData(config.startAt, ValidUntil.wrap(0));
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
        uint48 interval = uint48(bytes6(_data[0:6]));
        uint48 count = uint48(bytes6(_data[6:12]));
        uint48 startAt = uint48(bytes6(_data[12:18]));
        throttleConfigs[id][msg.sender] = ThrottleConfig(interval, count, ValidAfter.wrap(startAt));
        status[id][msg.sender] = Status.Live;
    }

    function _policyOnUninstall(bytes32 id, bytes calldata) internal override {
        require(status[id][msg.sender] == Status.Live, PolicyNotLive());
        status[id][msg.sender] = Status.Deprecated;
    }
}
