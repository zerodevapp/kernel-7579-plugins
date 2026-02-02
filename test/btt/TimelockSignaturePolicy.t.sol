// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {TimelockPolicy} from "src/policies/TimelockPolicy.sol";
import {IModule} from "src/interfaces/IERC7579Modules.sol";
import {ERC1271_MAGICVALUE, ERC1271_INVALID} from "src/types/Constants.sol";

/**
 * @title TimelockSignaturePolicyTest
 * @notice BTT tests for ERC-1271 signature validation with timelock enforcement
 * @dev Tests the fix that prevents bypassing timelock via ERC-1271 signatures
 */
contract TimelockSignaturePolicyTest is Test {
    TimelockPolicy public timelockPolicy;

    address constant WALLET = address(0x1234);
    address constant OTHER_ACCOUNT = address(0x5678);

    uint48 constant DELAY = 1 days;
    uint48 constant EXPIRATION_PERIOD = 1 days;

    bytes32 public policyId;
    bytes32 public testHash;

    function setUp() public {
        timelockPolicy = new TimelockPolicy();
        policyId = keccak256(abi.encodePacked("POLICY_ID_1"));
        testHash = keccak256(abi.encodePacked("TEST_HASH_TO_SIGN"));
    }

    /// @notice Helper to install the policy for a wallet
    function _installPolicy(address wallet) internal {
        bytes memory installData = abi.encode(DELAY, EXPIRATION_PERIOD);
        vm.prank(wallet);
        timelockPolicy.onInstall(abi.encodePacked(policyId, installData));
    }

    /// @notice Helper to create a signature proposal
    function _createSignatureProposal(address wallet, bytes32 hash) internal {
        timelockPolicy.createSignatureProposal(policyId, wallet, hash);
    }

    // ============================================================
    // Test: when policy is not installed
    // ============================================================

    function test_WhenPolicyIsNotInstalled() external {
        // it should return ERC1271_INVALID for signature validation

        // Do NOT install the policy for WALLET

        // Try to validate a signature without installation
        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkSignaturePolicy(policyId, address(0), testHash, "");

        // Should return 1 (failure) because policy is not initialized
        assertEq(result, 1, "Should return validation failure when policy not installed");
    }

    // ============================================================
    // Test: when creating signature proposal without initialization
    // ============================================================

    function test_WhenCreatingSignatureProposalWithoutInitialization() external {
        // it should revert with NotInitialized

        // Do NOT install the policy

        // Attempt to create a signature proposal should revert
        vm.expectRevert(abi.encodeWithSelector(IModule.NotInitialized.selector, WALLET));
        timelockPolicy.createSignatureProposal(policyId, WALLET, testHash);
    }

    // ============================================================
    // Test: when creating signature proposal that already exists
    // ============================================================

    function test_WhenCreatingSignatureProposalThatAlreadyExists() external {
        // it should revert with ProposalAlreadyExists

        // Install policy
        _installPolicy(WALLET);

        // Create first signature proposal
        _createSignatureProposal(WALLET, testHash);

        // Attempt to create the same proposal again should revert
        vm.expectRevert(TimelockPolicy.ProposalAlreadyExists.selector);
        _createSignatureProposal(WALLET, testHash);
    }

    // ============================================================
    // Test: when creating signature proposal successfully
    // ============================================================

    function test_WhenCreatingSignatureProposalSuccessfully() external {
        // it should store the proposal with Pending status
        // it should set validAfter to timestamp plus delay
        // it should set validUntil to validAfter plus expiration

        // Install policy
        _installPolicy(WALLET);

        uint256 currentTimestamp = block.timestamp;

        // Create signature proposal
        _createSignatureProposal(WALLET, testHash);

        // Verify proposal details
        (TimelockPolicy.ProposalStatus status, uint256 validAfter, uint256 validUntil) =
            timelockPolicy.getSignatureProposal(testHash, policyId, WALLET);

        // Check status is Pending
        assertEq(
            uint256(status),
            uint256(TimelockPolicy.ProposalStatus.Pending),
            "Proposal status should be Pending"
        );

        // Check validAfter is timestamp + delay
        assertEq(
            validAfter,
            currentTimestamp + DELAY,
            "validAfter should be current timestamp plus delay"
        );

        // Check validUntil is validAfter + expiration
        assertEq(
            validUntil,
            currentTimestamp + DELAY + EXPIRATION_PERIOD,
            "validUntil should be validAfter plus expiration period"
        );
    }

    // ============================================================
    // Test: when cancelling signature proposal as non-account
    // ============================================================

    function test_WhenCancellingSignatureProposalAsNon_account() external {
        // it should revert with OnlyAccount

        // Install policy
        _installPolicy(WALLET);

        // Create signature proposal
        _createSignatureProposal(WALLET, testHash);

        // Attempt to cancel from a different account should revert
        vm.prank(OTHER_ACCOUNT);
        vm.expectRevert(TimelockPolicy.OnlyAccount.selector);
        timelockPolicy.cancelSignatureProposal(policyId, WALLET, testHash);
    }

    // ============================================================
    // Test: when cancelling signature proposal successfully
    // ============================================================

    function test_WhenCancellingSignatureProposalSuccessfully() external {
        // it should set the proposal status to Cancelled

        // Install policy
        _installPolicy(WALLET);

        // Create signature proposal
        _createSignatureProposal(WALLET, testHash);

        // Verify it is pending first
        (TimelockPolicy.ProposalStatus statusBefore,,) =
            timelockPolicy.getSignatureProposal(testHash, policyId, WALLET);
        assertEq(
            uint256(statusBefore),
            uint256(TimelockPolicy.ProposalStatus.Pending),
            "Proposal should be Pending before cancellation"
        );

        // Cancel the proposal as the account owner
        vm.prank(WALLET);
        timelockPolicy.cancelSignatureProposal(policyId, WALLET, testHash);

        // Verify status is now Cancelled
        (TimelockPolicy.ProposalStatus statusAfter,,) =
            timelockPolicy.getSignatureProposal(testHash, policyId, WALLET);
        assertEq(
            uint256(statusAfter),
            uint256(TimelockPolicy.ProposalStatus.Cancelled),
            "Proposal status should be Cancelled after cancellation"
        );
    }

    // ============================================================
    // Test: when checking signature without proposal
    // ============================================================

    function test_WhenCheckingSignatureWithoutProposal() external {
        // it should return validation failure

        // Install policy
        _installPolicy(WALLET);

        // Do NOT create a signature proposal

        // Try to validate signature
        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkSignaturePolicy(policyId, address(0), testHash, "");

        // Should return 1 (failure) because no proposal exists
        assertEq(result, 1, "Should return validation failure when no proposal exists");
    }

    // ============================================================
    // Test: when checking signature before timelock passes
    // ============================================================

    function test_WhenCheckingSignatureBeforeTimelockPasses() external {
        // it should return validation failure

        // Install policy
        _installPolicy(WALLET);

        // Create signature proposal
        _createSignatureProposal(WALLET, testHash);

        // Do NOT warp time - we are still in the pending period

        // Try to validate signature immediately
        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkSignaturePolicy(policyId, address(0), testHash, "");

        // Should return 1 (failure) because timelock has not passed
        assertEq(result, 1, "Should return validation failure before timelock passes");
    }

    // ============================================================
    // Test: when checking signature after timelock passes
    // ============================================================

    function test_WhenCheckingSignatureAfterTimelockPasses() external {
        // it should return validation success

        // Install policy
        _installPolicy(WALLET);

        // Create signature proposal
        _createSignatureProposal(WALLET, testHash);

        // Warp time past the delay but before expiration
        vm.warp(block.timestamp + DELAY + 1);

        // Validate signature
        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkSignaturePolicy(policyId, address(0), testHash, "");

        // Should return 0 (success) because timelock has passed and proposal is valid
        assertEq(result, 0, "Should return validation success after timelock passes");
    }

    // ============================================================
    // Test: when checking signature after expiration
    // ============================================================

    function test_WhenCheckingSignatureAfterExpiration() external {
        // it should return validation failure

        // Install policy
        _installPolicy(WALLET);

        // Create signature proposal
        _createSignatureProposal(WALLET, testHash);

        // Warp time past the expiration (delay + expiration + 1 second)
        vm.warp(block.timestamp + DELAY + EXPIRATION_PERIOD + 1);

        // Try to validate signature after expiration
        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkSignaturePolicy(policyId, address(0), testHash, "");

        // Should return 1 (failure) because proposal has expired
        assertEq(result, 1, "Should return validation failure after expiration");
    }

    // ============================================================
    // Test: when checking signature for cancelled proposal
    // ============================================================

    function test_WhenCheckingSignatureForCancelledProposal() external {
        // it should return validation failure

        // Install policy
        _installPolicy(WALLET);

        // Create signature proposal
        _createSignatureProposal(WALLET, testHash);

        // Cancel the proposal
        vm.prank(WALLET);
        timelockPolicy.cancelSignatureProposal(policyId, WALLET, testHash);

        // Warp time past the delay (would normally be valid)
        vm.warp(block.timestamp + DELAY + 1);

        // Try to validate signature for cancelled proposal
        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkSignaturePolicy(policyId, address(0), testHash, "");

        // Should return 1 (failure) because proposal is cancelled
        assertEq(result, 1, "Should return validation failure for cancelled proposal");
    }
}
