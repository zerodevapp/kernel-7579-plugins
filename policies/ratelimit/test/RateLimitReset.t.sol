pragma solidity ^0.8.0;

import "src/RateLimitPolicyReset.sol";

import "forge-std/Test.sol";

contract RateLimitPolicyResetTest is Test {
    RateLimitPolicyReset policy;

    address caller;

    function setUp() external {
        policy = new RateLimitPolicyReset();
        caller = makeAddr("Caller");
    }

    function testOnInstall(bytes32 id, uint48 interval, uint48 allowedCallCount) external {
        vm.assume(block.timestamp + uint256(interval) < type(uint48).max);
        vm.startPrank(caller);
        policy.onInstall(abi.encodePacked(id, interval, allowedCallCount));
        vm.stopPrank();

        Status s = policy.status(id, caller);
        assertEq(uint8(s), uint8(Status.Live));
        assertEq(policy.usedIds(caller), 1);

        (uint48 cfgInterval, uint48 cfgCount) = policy.rateLimitConfigs(id, caller);
        assertEq(cfgInterval, interval);
        assertEq(cfgCount, allowedCallCount);

        (uint48 stateCount, uint48 stateResetTime) = policy.rateLimitState(id, caller);
        assertEq(stateCount, allowedCallCount);
        assertEq(stateResetTime, block.timestamp + interval);
    }

    function testCheckUserOp(bytes32 id) external {
        uint48 interval = 100; //100 seconds
        uint48 allowedCallCount = 10; // you are only allowed to call 10 times within 100 seconds
        vm.startPrank(caller);
        policy.onInstall(abi.encodePacked(id, interval, allowedCallCount));
        vm.stopPrank();

        // check initial state
        Status s = policy.status(id, caller);
        assertEq(uint8(s), uint8(Status.Live));
        assertEq(policy.usedIds(caller), 1);

        (uint48 cfgInterval, uint48 cfgCount) = policy.rateLimitConfigs(id, caller);
        assertEq(cfgInterval, interval);
        assertEq(cfgCount, allowedCallCount);

        (uint48 stateCount, uint48 stateResetTime) = policy.rateLimitState(id, caller);
        assertEq(stateCount, allowedCallCount);
        assertEq(stateResetTime, block.timestamp + interval);

        // store next Reset;
        uint48 nextReset = stateResetTime;

        // check if call can happen up to allowedCallCount
        for (uint48 c; c < allowedCallCount; c++) {
            vm.startPrank(caller);
            PackedUserOperation memory empty;
            policy.checkUserOpPolicy(id, empty);
            vm.stopPrank();

            (stateCount, stateResetTime) = policy.rateLimitState(id, caller);
            assertEq(stateCount, allowedCallCount - c - 1);
            assertEq(stateResetTime, stateResetTime);
        }

        // sanity check if rateLimited
        (stateCount, stateResetTime) = policy.rateLimitState(id, caller);
        assertEq(stateCount, 0);
        assertEq(stateResetTime, stateResetTime);
        // check call fails after alloweCallCount is used up
        vm.startPrank(caller);
        PackedUserOperation memory empty;
        vm.expectRevert(RateLimitPolicyReset.RateLimited.selector);
        policy.checkUserOpPolicy(id, empty);
        vm.stopPrank();

        // sanity check
        (stateCount, stateResetTime) = policy.rateLimitState(id, caller);
        assertEq(stateCount, 0);
        assertEq(stateResetTime, stateResetTime);

        // warp
        vm.warp(stateResetTime);
        stateResetTime = stateResetTime + interval;
        // check if call can happen up to allowedCallCount, and check if stateResetTime remains same even if blockTimestamp increases
        for (uint48 c; c < allowedCallCount; c++) {
            vm.warp(block.timestamp + 1); // increase 1 sec
            vm.startPrank(caller);
            PackedUserOperation memory empty;
            policy.checkUserOpPolicy(id, empty);
            vm.stopPrank();

            (stateCount, stateResetTime) = policy.rateLimitState(id, caller);
            assertEq(stateCount, allowedCallCount - c - 1);
            assertEq(stateResetTime, stateResetTime);
        }

        // sanity check
        (stateCount, stateResetTime) = policy.rateLimitState(id, caller);
        assertEq(stateCount, 0);
        assertEq(stateResetTime, stateResetTime);

        // warp
        vm.warp(stateResetTime);
        stateResetTime = stateResetTime + interval;
        // check if count is reset even if count is not used up
        for (uint48 c; c < allowedCallCount - 2; c++) {
            vm.warp(block.timestamp + 1); // increase timeframe by a bit
            vm.startPrank(caller);
            policy.checkUserOpPolicy(id, empty);
            vm.stopPrank();

            (stateCount, stateResetTime) = policy.rateLimitState(id, caller);
            assertEq(stateCount, allowedCallCount - c - 1);
            assertEq(stateResetTime, stateResetTime);
        }

        assertEq(stateCount, 2);
        assertEq(stateResetTime, stateResetTime);

        vm.warp(stateResetTime);
        vm.startPrank(caller);
        policy.checkUserOpPolicy(id, empty);
        (stateCount, stateResetTime) = policy.rateLimitState(id, caller);
        assertEq(stateCount, allowedCallCount - 1);
        assertEq(stateResetTime, block.timestamp + interval);
        vm.stopPrank();
    }
}
