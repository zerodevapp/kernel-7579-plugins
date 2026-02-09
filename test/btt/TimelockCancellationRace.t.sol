// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {TimelockPolicy} from "src/policies/TimelockPolicy.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IModule} from "src/interfaces/IERC7579Modules.sol";

/**
 * @title TimelockCancellationRaceTest
 * @notice BTT tests for the TimelockPolicy cancellation and grace period fix (TOB-KERNEL-21)
 * @dev This test suite verifies that:
 *      1. Cancelled proposals cannot be executed
 *      2. Grace period prevents race conditions between cancellation and execution
 *      3. The owner can cancel during grace period before public execution
 */
contract TimelockCancellationRaceTest is Test {
    TimelockPolicy public timelockPolicy;

    address constant WALLET = address(0x1234);
    address constant ATTACKER = address(0xBAD);

    uint48 constant DELAY = 1 days;
    uint48 constant EXPIRATION_PERIOD = 1 days;
    uint48 constant GRACE_PERIOD = 1 hours;

    bytes32 public policyId;

    // Test calldata and nonce for proposals
    bytes constant TEST_CALLDATA = hex"1234abcd";
    uint256 constant TEST_NONCE = 1;

    function setUp() public {
        timelockPolicy = new TimelockPolicy();
        policyId = keccak256(abi.encodePacked("POLICY_ID_1"));

        // Install policy for WALLET
        vm.startPrank(WALLET);
        timelockPolicy.onInstall(abi.encodePacked(policyId, abi.encode(DELAY, EXPIRATION_PERIOD, GRACE_PERIOD)));
        vm.stopPrank();
    }

    // Helper function to create a proposal via no-op UserOp
    function _createProposal(bytes memory callData, uint256 nonce) internal {
        bytes memory sig = abi.encodePacked(bytes32(callData.length), callData, bytes32(nonce), bytes1(0x00));
        PackedUserOperation memory noopOp = PackedUserOperation({
            sender: WALLET,
            nonce: 0,
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(abi.encodePacked(uint128(100000), uint128(200000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: "",
            signature: sig
        });
        vm.prank(WALLET);
        timelockPolicy.checkUserOpPolicy(policyId, noopOp);
    }

    // Helper function to cancel a proposal
    function _cancelProposal(bytes memory callData, uint256 nonce) internal {
        vm.prank(WALLET);
        timelockPolicy.cancelProposal(policyId, WALLET, callData, nonce);
    }

    // Helper function to create a userOp for execution
    function _createUserOp(bytes memory callData, uint256 nonce) internal pure returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: WALLET,
            nonce: nonce,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(100000), uint128(200000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: "",
            signature: ""
        });
    }

    // Helper to extract validAfter from packed validation data
    function _extractValidAfter(uint256 validationData) internal pure returns (uint48) {
        return uint48(validationData >> 208);
    }

    // Helper to extract validUntil from packed validation data
    function _extractValidUntil(uint256 validationData) internal pure returns (uint48) {
        return uint48(validationData >> 160);
    }

    // ==================== whenCancellingAProposal ====================

    modifier whenCancellingAProposal() {
        _;
    }

    function test_GivenTheProposalIsPending() external whenCancellingAProposal {
        // Setup: Create a pending proposal
        _createProposal(TEST_CALLDATA, TEST_NONCE);

        // Verify proposal is pending before cancellation
        (TimelockPolicy.ProposalStatus statusBefore,,,) =
            timelockPolicy.getProposal(WALLET, TEST_CALLDATA, TEST_NONCE, policyId, WALLET);
        assertEq(uint256(statusBefore), uint256(TimelockPolicy.ProposalStatus.Pending), "Proposal should be pending");

        // Action: Cancel the proposal and expect event
        bytes32 expectedUserOpKey = timelockPolicy.computeUserOpKey(WALLET, TEST_CALLDATA, TEST_NONCE);

        vm.expectEmit(true, true, true, true);
        emit TimelockPolicy.ProposalCancelled(WALLET, policyId, expectedUserOpKey);

        _cancelProposal(TEST_CALLDATA, TEST_NONCE);

        // Verify: it should set proposal status to Cancelled
        (TimelockPolicy.ProposalStatus statusAfter,,,) =
            timelockPolicy.getProposal(WALLET, TEST_CALLDATA, TEST_NONCE, policyId, WALLET);
        assertEq(uint256(statusAfter), uint256(TimelockPolicy.ProposalStatus.Cancelled), "Proposal should be cancelled");

        // Verify: it should prevent execution via checkUserOpPolicy returning failure
        PackedUserOperation memory userOp = _createUserOp(TEST_CALLDATA, TEST_NONCE);
        vm.prank(WALLET);
        uint256 validationResult = timelockPolicy.checkUserOpPolicy(policyId, userOp);
        assertEq(validationResult, 1, "Execution should fail for cancelled proposal (SIG_VALIDATION_FAILED)");
    }

    function test_GivenTheProposalDoesNotExist() external whenCancellingAProposal {
        // Action & Verify: it should revert with ProposalNotPending
        vm.prank(WALLET);
        vm.expectRevert(TimelockPolicy.ProposalNotPending.selector);
        timelockPolicy.cancelProposal(policyId, WALLET, TEST_CALLDATA, TEST_NONCE);
    }

    function test_GivenTheProposalIsAlreadyCancelled() external whenCancellingAProposal {
        // Setup: Create and cancel a proposal
        _createProposal(TEST_CALLDATA, TEST_NONCE);
        _cancelProposal(TEST_CALLDATA, TEST_NONCE);

        // Action & Verify: it should revert with ProposalNotPending
        vm.prank(WALLET);
        vm.expectRevert(TimelockPolicy.ProposalNotPending.selector);
        timelockPolicy.cancelProposal(policyId, WALLET, TEST_CALLDATA, TEST_NONCE);
    }

    function test_GivenTheProposalIsAlreadyExecuted() external whenCancellingAProposal {
        // Setup: Create a proposal
        _createProposal(TEST_CALLDATA, TEST_NONCE);

        // Fast forward past delay AND grace period
        vm.warp(block.timestamp + DELAY + GRACE_PERIOD + 1);

        // Execute the proposal
        PackedUserOperation memory userOp = _createUserOp(TEST_CALLDATA, TEST_NONCE);
        vm.prank(WALLET);
        uint256 validationResult = timelockPolicy.checkUserOpPolicy(policyId, userOp);
        assertFalse(validationResult == 1, "Execution should succeed");

        // Verify proposal is executed
        (TimelockPolicy.ProposalStatus status,,,) =
            timelockPolicy.getProposal(WALLET, TEST_CALLDATA, TEST_NONCE, policyId, WALLET);
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Executed), "Proposal should be executed");

        // Action & Verify: it should revert with ProposalNotPending
        vm.prank(WALLET);
        vm.expectRevert(TimelockPolicy.ProposalNotPending.selector);
        timelockPolicy.cancelProposal(policyId, WALLET, TEST_CALLDATA, TEST_NONCE);
    }

    function test_GivenTheCallerIsNotTheAccount() external whenCancellingAProposal {
        // Setup: Create a proposal
        _createProposal(TEST_CALLDATA, TEST_NONCE);

        // Action & Verify: it should revert with OnlyAccount when attacker tries to cancel
        vm.prank(ATTACKER);
        vm.expectRevert(TimelockPolicy.OnlyAccount.selector);
        timelockPolicy.cancelProposal(policyId, WALLET, TEST_CALLDATA, TEST_NONCE);
    }

    // ==================== whenExecutingAProposalAfterCancellation ====================

    modifier whenExecutingAProposalAfterCancellation() {
        _;
    }

    function test_GivenTheProposalWasJustCancelledInTheSameBlock() external whenExecutingAProposalAfterCancellation {
        // Setup: Create a proposal
        _createProposal(TEST_CALLDATA, TEST_NONCE);

        // Fast forward past delay and grace period (to make it executable normally)
        vm.warp(block.timestamp + DELAY + GRACE_PERIOD + 1);

        // Cancel in the same block as execution attempt
        _cancelProposal(TEST_CALLDATA, TEST_NONCE);

        // Action: Try to execute in the same block
        PackedUserOperation memory userOp = _createUserOp(TEST_CALLDATA, TEST_NONCE);
        vm.prank(WALLET);
        uint256 validationResult = timelockPolicy.checkUserOpPolicy(policyId, userOp);

        // Verify: it should return SIG_VALIDATION_FAILED because status is Cancelled
        assertEq(validationResult, 1, "Should return SIG_VALIDATION_FAILED for cancelled proposal");
    }

    function test_GivenTheCancellationHappenedInAPreviousBlock() external whenExecutingAProposalAfterCancellation {
        // Setup: Create a proposal
        _createProposal(TEST_CALLDATA, TEST_NONCE);

        // Fast forward past delay and grace period
        vm.warp(block.timestamp + DELAY + GRACE_PERIOD + 1);

        // Cancel the proposal
        _cancelProposal(TEST_CALLDATA, TEST_NONCE);

        // Move to next block
        vm.warp(block.timestamp + 1);
        vm.roll(block.number + 1);

        // Action: Try to execute in a later block
        PackedUserOperation memory userOp = _createUserOp(TEST_CALLDATA, TEST_NONCE);
        vm.prank(WALLET);
        uint256 validationResult = timelockPolicy.checkUserOpPolicy(policyId, userOp);

        // Verify: it should return SIG_VALIDATION_FAILED because status is Cancelled
        assertEq(validationResult, 1, "Should return SIG_VALIDATION_FAILED for cancelled proposal");
    }

    function test_GivenANewProposalIsCreatedForTheSameCalldataAfterCancellation()
        external
        whenExecutingAProposalAfterCancellation
    {
        // Setup: Create and cancel a proposal
        _createProposal(TEST_CALLDATA, TEST_NONCE);
        _cancelProposal(TEST_CALLDATA, TEST_NONCE);

        // Note: Cancelled proposals persist. Attempting to create via no-op UserOp
        // for the same calldata/nonce returns SIG_VALIDATION_FAILED.
        bytes memory sig = abi.encodePacked(bytes32(TEST_CALLDATA.length), TEST_CALLDATA, bytes32(TEST_NONCE), bytes1(0x00));
        PackedUserOperation memory retryOp = PackedUserOperation({
            sender: WALLET,
            nonce: 0,
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(abi.encodePacked(uint128(100000), uint128(200000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: "",
            signature: sig
        });
        vm.prank(WALLET);
        uint256 retryResult = timelockPolicy.checkUserOpPolicy(policyId, retryOp);
        assertEq(retryResult, 1, "Should return SIG_VALIDATION_FAILED for cancelled proposal");

        // However, a proposal with different nonce should work
        uint256 newNonce = TEST_NONCE + 1;
        _createProposal(TEST_CALLDATA, newNonce);

        // Fast forward past delay and grace period
        vm.warp(block.timestamp + DELAY + GRACE_PERIOD + 1);

        // Execute the new proposal
        PackedUserOperation memory userOp = _createUserOp(TEST_CALLDATA, newNonce);
        vm.prank(WALLET);
        uint256 validationResult = timelockPolicy.checkUserOpPolicy(policyId, userOp);

        // Verify: it should allow execution of the new proposal after grace period
        assertFalse(validationResult == 1, "New proposal should be executable");

        // Verify status is executed
        (TimelockPolicy.ProposalStatus status,,,) =
            timelockPolicy.getProposal(WALLET, TEST_CALLDATA, newNonce, policyId, WALLET);
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Executed), "New proposal should be executed");
    }

    // ==================== whenExecutingAProposalDuringTheGracePeriod ====================

    modifier whenExecutingAProposalDuringTheGracePeriod() {
        _;
    }

    function test_GivenTheTimelockDelayHasPassedButGracePeriodHasNot()
        external
        whenExecutingAProposalDuringTheGracePeriod
    {
        // Setup: Create a proposal
        uint256 startTime = block.timestamp;
        _createProposal(TEST_CALLDATA, TEST_NONCE);

        // Get expected timing - note: packed validAfter uses graceEnd
        (,uint256 validAfter, uint256 graceEnd, uint256 validUntil) =
            timelockPolicy.getProposal(WALLET, TEST_CALLDATA, TEST_NONCE, policyId, WALLET);

        // Fast forward past delay but NOT past grace period
        vm.warp(startTime + DELAY + 1);

        // Verify we are in the grace period window
        assertTrue(block.timestamp > validAfter, "Should be past validAfter");
        assertTrue(block.timestamp < graceEnd, "Should be before graceEnd");
        assertTrue(block.timestamp < validUntil, "Should be before validUntil");

        // Action: Try to execute
        PackedUserOperation memory userOp = _createUserOp(TEST_CALLDATA, TEST_NONCE);
        vm.prank(WALLET);
        uint256 validationResult = timelockPolicy.checkUserOpPolicy(policyId, userOp);

        // Verify: it should return validation data with graceEnd as validAfter
        assertFalse(validationResult == 1, "Should not return failure");

        uint48 returnedValidAfter = _extractValidAfter(validationResult);
        uint48 returnedValidUntil = _extractValidUntil(validationResult);

        // The returned validAfter is graceEnd (not validAfter)
        // This is the key fix - prevents execution during grace period
        assertEq(returnedValidAfter, uint48(graceEnd), "validAfter should be graceEnd");
        assertEq(returnedValidUntil, uint48(validUntil), "validUntil should match proposal expiration");

        // Note: The bundler/EntryPoint would reject execution during grace period
        // because block.timestamp < returnedValidAfter (graceEnd)
    }

    function test_GivenTheGracePeriodHasPassed() external whenExecutingAProposalDuringTheGracePeriod {
        // Setup: Create a proposal
        uint256 startTime = block.timestamp;
        _createProposal(TEST_CALLDATA, TEST_NONCE);

        // Get timing info
        (,uint256 validAfter,, uint256 validUntil) =
            timelockPolicy.getProposal(WALLET, TEST_CALLDATA, TEST_NONCE, policyId, WALLET);

        // Fast forward past delay AND grace period
        vm.warp(startTime + DELAY + GRACE_PERIOD + 1);

        // Verify we are past the grace period
        assertTrue(block.timestamp > validAfter, "Should be past graceEnd");
        assertTrue(block.timestamp < validUntil, "Should be before validUntil");

        // Action: Execute
        PackedUserOperation memory userOp = _createUserOp(TEST_CALLDATA, TEST_NONCE);
        vm.prank(WALLET);
        uint256 validationResult = timelockPolicy.checkUserOpPolicy(policyId, userOp);

        // Verify: it should return validation data allowing execution
        assertFalse(validationResult == 1, "Should not return failure");

        uint48 returnedValidAfter = _extractValidAfter(validationResult);
        assertTrue(block.timestamp >= returnedValidAfter, "Should be past validAfter for execution");

        // Verify: it should set proposal status to Executed
        (TimelockPolicy.ProposalStatus status,,,) =
            timelockPolicy.getProposal(WALLET, TEST_CALLDATA, TEST_NONCE, policyId, WALLET);
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Executed), "Proposal should be executed");
    }

    // ==================== whenTheOwnerCancelsDuringGracePeriod ====================

    modifier whenTheOwnerCancelsDuringGracePeriod() {
        _;
    }

    function test_GivenTheProposalIsStillPending() external whenTheOwnerCancelsDuringGracePeriod {
        // Setup: Create a proposal
        uint256 startTime = block.timestamp;
        _createProposal(TEST_CALLDATA, TEST_NONCE);

        // Fast forward to grace period (past delay, but before validUntil)
        vm.warp(startTime + DELAY + 1);

        // Verify proposal is still pending
        (TimelockPolicy.ProposalStatus statusBefore,,,) =
            timelockPolicy.getProposal(WALLET, TEST_CALLDATA, TEST_NONCE, policyId, WALLET);
        assertEq(uint256(statusBefore), uint256(TimelockPolicy.ProposalStatus.Pending), "Proposal should still be pending");

        // Action: Owner cancels during grace period
        _cancelProposal(TEST_CALLDATA, TEST_NONCE);

        // Verify: it should successfully cancel the proposal
        (TimelockPolicy.ProposalStatus statusAfter,,,) =
            timelockPolicy.getProposal(WALLET, TEST_CALLDATA, TEST_NONCE, policyId, WALLET);
        assertEq(uint256(statusAfter), uint256(TimelockPolicy.ProposalStatus.Cancelled), "Proposal should be cancelled");
    }

    function test_GivenAnExecutionAttemptIsPendingInTheMempool() external whenTheOwnerCancelsDuringGracePeriod {
        // Setup: Create a proposal
        uint256 startTime = block.timestamp;
        _createProposal(TEST_CALLDATA, TEST_NONCE);

        // Fast forward to grace period
        vm.warp(startTime + DELAY + 1);

        // Simulate scenario where both cancellation and execution happen in same block
        // but cancellation is processed first (wins the race)

        // Owner cancels first
        _cancelProposal(TEST_CALLDATA, TEST_NONCE);

        // Then execution attempt comes in the same block
        PackedUserOperation memory userOp = _createUserOp(TEST_CALLDATA, TEST_NONCE);
        vm.prank(WALLET);
        uint256 validationResult = timelockPolicy.checkUserOpPolicy(policyId, userOp);

        // Verify: it should allow cancellation to win the race (execution fails)
        assertEq(validationResult, 1, "Execution should fail because cancellation won the race");

        // Verify proposal remains cancelled
        (TimelockPolicy.ProposalStatus status,,,) =
            timelockPolicy.getProposal(WALLET, TEST_CALLDATA, TEST_NONCE, policyId, WALLET);
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Cancelled), "Proposal should remain cancelled");
    }

    // ==================== whenAttemptingMultipleCancellations ====================

    modifier whenAttemptingMultipleCancellations() {
        _;
    }

    function test_GivenTheProposalWasJustCancelled() external whenAttemptingMultipleCancellations {
        // Setup: Create and cancel a proposal
        _createProposal(TEST_CALLDATA, TEST_NONCE);
        _cancelProposal(TEST_CALLDATA, TEST_NONCE);

        // Move to next block
        vm.warp(block.timestamp + 1);
        vm.roll(block.number + 1);

        // Action & Verify: it should revert with ProposalNotPending on second attempt
        vm.prank(WALLET);
        vm.expectRevert(TimelockPolicy.ProposalNotPending.selector);
        timelockPolicy.cancelProposal(policyId, WALLET, TEST_CALLDATA, TEST_NONCE);
    }

    function test_GivenTryingToCancelTwiceInTheSameTransaction() external whenAttemptingMultipleCancellations {
        // Setup: Create a proposal
        _createProposal(TEST_CALLDATA, TEST_NONCE);

        // Action: First cancellation succeeds
        vm.startPrank(WALLET);
        timelockPolicy.cancelProposal(policyId, WALLET, TEST_CALLDATA, TEST_NONCE);

        // Verify: it should revert with ProposalNotPending on second call
        vm.expectRevert(TimelockPolicy.ProposalNotPending.selector);
        timelockPolicy.cancelProposal(policyId, WALLET, TEST_CALLDATA, TEST_NONCE);
        vm.stopPrank();
    }

    // ==================== whenCreatingANewProposalAfterGracePeriod ====================

    modifier whenCreatingANewProposalAfterGracePeriod() {
        _;
    }

    function test_GivenTheOriginalProposalWasCancelled() external whenCreatingANewProposalAfterGracePeriod {
        // Setup: Create and cancel a proposal
        _createProposal(TEST_CALLDATA, TEST_NONCE);
        _cancelProposal(TEST_CALLDATA, TEST_NONCE);

        // Fast forward past when grace period would have ended
        vm.warp(block.timestamp + DELAY + GRACE_PERIOD + EXPIRATION_PERIOD + 1);

        // Action & Verify: Attempting to create via no-op UserOp returns SIG_VALIDATION_FAILED
        // because cancelled proposals persist in storage
        bytes memory sig = abi.encodePacked(bytes32(TEST_CALLDATA.length), TEST_CALLDATA, bytes32(TEST_NONCE), bytes1(0x00));
        PackedUserOperation memory noopOp = PackedUserOperation({
            sender: WALLET,
            nonce: 0,
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(abi.encodePacked(uint128(100000), uint128(200000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: "",
            signature: sig
        });
        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(policyId, noopOp);
        assertEq(result, 1, "Should return SIG_VALIDATION_FAILED because cancelled proposals persist");
    }

    function test_GivenTheOriginalProposalWasExecuted() external whenCreatingANewProposalAfterGracePeriod {
        // Setup: Create a proposal
        _createProposal(TEST_CALLDATA, TEST_NONCE);

        // Fast forward past delay and grace period
        vm.warp(block.timestamp + DELAY + GRACE_PERIOD + 1);

        // Execute the proposal
        PackedUserOperation memory userOp = _createUserOp(TEST_CALLDATA, TEST_NONCE);
        vm.prank(WALLET);
        timelockPolicy.checkUserOpPolicy(policyId, userOp);

        // Fast forward more
        vm.warp(block.timestamp + EXPIRATION_PERIOD + 1);

        // Action & Verify: Attempting to create via no-op UserOp returns SIG_VALIDATION_FAILED
        // because executed proposals persist in storage
        bytes memory sig = abi.encodePacked(bytes32(TEST_CALLDATA.length), TEST_CALLDATA, bytes32(TEST_NONCE), bytes1(0x00));
        PackedUserOperation memory noopOp = PackedUserOperation({
            sender: WALLET,
            nonce: 0,
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(abi.encodePacked(uint128(100000), uint128(200000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: "",
            signature: sig
        });
        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(policyId, noopOp);
        assertEq(result, 1, "Should return SIG_VALIDATION_FAILED because executed proposals persist");
    }

    // ==================== whenValidatingGracePeriodTiming ====================

    modifier whenValidatingGracePeriodTiming() {
        _;
    }

    function test_GivenDelayIs1DayAndGracePeriodIs1Hour() external whenValidatingGracePeriodTiming {
        // Setup: Record start time
        uint256 startTime = block.timestamp;

        // Action: Create a proposal
        _createProposal(TEST_CALLDATA, TEST_NONCE);

        // Get proposal timing
        (TimelockPolicy.ProposalStatus status, uint256 validAfter,, uint256 validUntil) =
            timelockPolicy.getProposal(WALLET, TEST_CALLDATA, TEST_NONCE, policyId, WALLET);

        // Verify: it should set validAfter to current time plus delay
        assertEq(validAfter, startTime + DELAY, "validAfter should be startTime + delay");

        // Verify: it should set validUntil correctly (validAfter + grace + expiration)
        assertEq(validUntil, validAfter + GRACE_PERIOD + EXPIRATION_PERIOD, "validUntil should be validAfter + gracePeriod + expirationPeriod");
    }

    function test_GivenExecutionValidationDataIsReturned() external whenValidatingGracePeriodTiming {
        // Setup: Create a proposal
        uint256 startTime = block.timestamp;
        _createProposal(TEST_CALLDATA, TEST_NONCE);

        // Get expected timing - note: packed validAfter uses graceEnd, not validAfter
        (,uint256 expectedValidAfter, uint256 expectedGraceEnd, uint256 expectedValidUntil) =
            timelockPolicy.getProposal(WALLET, TEST_CALLDATA, TEST_NONCE, policyId, WALLET);

        // Fast forward just past delay but still in grace period
        vm.warp(startTime + DELAY + 1);

        // Action: Get validation data by calling checkUserOpPolicy
        PackedUserOperation memory userOp = _createUserOp(TEST_CALLDATA, TEST_NONCE);
        vm.prank(WALLET);
        uint256 validationResult = timelockPolicy.checkUserOpPolicy(policyId, userOp);

        // Extract packed values
        uint48 packedValidAfter = _extractValidAfter(validationResult);
        uint48 packedValidUntil = _extractValidUntil(validationResult);

        // Verify: it should pack graceEnd as validAfter (execution allowed after grace period)
        assertEq(packedValidAfter, uint48(expectedGraceEnd), "Packed validAfter should match proposal graceEnd");

        // Verify: it should pack validUntil as expiration time
        assertEq(packedValidUntil, uint48(expectedValidUntil), "Packed validUntil should match proposal expiration");
    }

    // ==================== Additional Edge Case Tests ====================

    function test_ExecutionFailsForExpiredProposal() external {
        // Setup: Create a proposal
        _createProposal(TEST_CALLDATA, TEST_NONCE);

        // Fast forward past expiration
        vm.warp(block.timestamp + DELAY + GRACE_PERIOD + EXPIRATION_PERIOD + 1);

        // Action: Try to execute
        PackedUserOperation memory userOp = _createUserOp(TEST_CALLDATA, TEST_NONCE);
        vm.prank(WALLET);
        uint256 validationResult = timelockPolicy.checkUserOpPolicy(policyId, userOp);

        // The proposal would be marked as executed in storage, but the validUntil
        // returned would be in the past, causing bundler rejection
        uint48 packedValidUntil = _extractValidUntil(validationResult);
        assertTrue(block.timestamp > packedValidUntil, "Current time should be past validUntil");
    }

    function test_NonInitializedAccountCannotCancelProposal() external {
        address nonInitializedAccount = address(0xDEAD);

        // Try to cancel on non-initialized account
        vm.prank(nonInitializedAccount);
        vm.expectRevert(abi.encodeWithSelector(IModule.NotInitialized.selector, nonInitializedAccount));
        timelockPolicy.cancelProposal(policyId, nonInitializedAccount, TEST_CALLDATA, TEST_NONCE);
    }

    function test_NonInitializedAccountCannotCreateProposal() external {
        address nonInitializedAccount = address(0xDEAD);

        // Try to create proposal via no-op UserOp on non-initialized account
        bytes memory sig = abi.encodePacked(bytes32(TEST_CALLDATA.length), TEST_CALLDATA, bytes32(TEST_NONCE), bytes1(0x00));
        PackedUserOperation memory noopOp = PackedUserOperation({
            sender: nonInitializedAccount,
            nonce: 0,
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(abi.encodePacked(uint128(100000), uint128(200000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: "",
            signature: sig
        });
        vm.prank(nonInitializedAccount);
        uint256 result = timelockPolicy.checkUserOpPolicy(policyId, noopOp);
        assertEq(result, 1, "Should return SIG_VALIDATION_FAILED for non-initialized account");
    }
}
