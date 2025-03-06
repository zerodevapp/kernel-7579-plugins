pragma solidity ^0.8.0;

import "kernel/sdk/moduleBase/PolicyBase.sol";
import {packValidationData, ValidAfter, ValidUntil} from "kernel/types/Types.sol";

enum Status {
    NA,
    Live,
    Deprecated
}

/// @notice Configuration for the naive rate limiter.
struct RateLimitConfig {
    uint48 interval; // Time window in seconds.
    uint48 initialCount; // Maximum number of operations allowed in each window.
}

/// @notice The current state for the naive rate limiter.
struct NaiveRateLimitState {
    uint48 storedCount; // Remaining allowed operations in the current window.
    uint48 resetDate; // Timestamp at which the current window ends.
}

import "forge-std/console.sol";

contract RateLimitPolicyReset is PolicyBase {
    error RateLimited();

    mapping(address => uint256) public usedIds;
    mapping(bytes32 id => mapping(address => Status)) public status;
    // Maps each policy id and wallet to its rate limiting configuration.
    mapping(bytes32 => mapping(address => RateLimitConfig)) public rateLimitConfigs;
    // Maps each policy id and wallet to its current rate limiting state.
    mapping(bytes32 => mapping(address => NaiveRateLimitState)) public rateLimitState;

    /// @notice Installs the policy with encoded configuration data.
    /// @dev Expects `_data` to be at least 12 bytes:
    ///      - first 6 bytes: uint48 interval,
    ///      - next 6 bytes: uint48 initialCount.
    function _policyOninstall(bytes32 id, bytes calldata _data) internal override {
        console.logBytes(_data);
        require(status[id][msg.sender] != Status.Live);
        require(_data.length >= 12, "Invalid data length");
        uint48 interval = uint48(bytes6(_data[0:6]));
        uint48 initialCount = uint48(bytes6(_data[6:12]));
        rateLimitConfigs[id][msg.sender] = RateLimitConfig(interval, initialCount);

        // Initialize the state: set storedCount to initialCount and resetDate to now + interval.
        rateLimitState[id][msg.sender] =
            NaiveRateLimitState({storedCount: initialCount, resetDate: uint48(block.timestamp) + interval});

        status[id][msg.sender] = Status.Live;
        usedIds[msg.sender]++;
    }

    function _policyOnUninstall(bytes32 id, bytes calldata _data) internal override {
        require(status[id][msg.sender] == Status.Live);
        status[id][msg.sender] = Status.Deprecated;
        usedIds[msg.sender]--;
    }

    /// @notice Checks the policy for a user operation.
    /// If the current time has passed the resetDate, it resets storedCount and resetDate.
    /// Then it decrements storedCount if there is quota remaining.
    function checkUserOpPolicy(bytes32 id, PackedUserOperation calldata /*userOp*/ )
        external
        payable
        override
        returns (uint256)
    {
        RateLimitConfig storage config = rateLimitConfigs[id][msg.sender];
        NaiveRateLimitState storage state = rateLimitState[id][msg.sender];
        uint48 currentTime = uint48(block.timestamp);

        // Reset the counter if the current time has passed the window's resetDate.
        if (currentTime >= state.resetDate) {
            state.storedCount = config.initialCount;
            state.resetDate = currentTime + config.interval;
        }

        require(state.storedCount > 0, RateLimited());
        // Decrement the allowed count.
        state.storedCount--;

        // Return validation data: current time and next reset date.
        return packValidationData(ValidAfter.wrap(currentTime), ValidUntil.wrap(state.resetDate));
    }

    /// @notice No signature validation is required for this policy.
    function checkSignaturePolicy(bytes32 id, address sender, bytes32 hash, bytes calldata sig)
        external
        view
        override
        returns (uint256)
    {
        return 0;
    }

    function isInitialized(address wallet) external view override returns (bool) {
        return rateLimitConfigs[keccak256(abi.encode(wallet))][wallet].initialCount > 0;
    }
}
