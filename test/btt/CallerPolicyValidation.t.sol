// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {CallerPolicy, Status} from "src/policies/CallerPolicy.sol";
import {IPolicy} from "src/interfaces/IERC7579Modules.sol";

/// @title CallerPolicyValidationTest
/// @notice BTT tests for the CallerPolicy caller validation fix (TOB-KERNEL-19)
/// @dev Tests the fix that validates callers array on install:
///      - Empty callers array should revert
///      - Zero address in callers should revert
///      - Valid callers should be properly registered
contract CallerPolicyValidationTest is Test {
    CallerPolicy public policy;

    address constant WALLET_1 = address(0x1234);
    address constant WALLET_2 = address(0x5678);
    address constant ALLOWED_CALLER_1 = address(0xCAFE);
    address constant ALLOWED_CALLER_2 = address(0xBEEF);
    address constant DISALLOWED_CALLER = address(0xDEAD);

    bytes32 constant POLICY_ID = keccak256("TEST_POLICY_ID");

    function setUp() public {
        policy = new CallerPolicy();
    }

    // ==================== Installation Tests ====================

    function test_WhenInstallingWithEmptyCallersArray() external {
        // it should revert with EmptyCallersArray
        address[] memory emptyCallers = new address[](0);
        bytes memory installData = abi.encodePacked(POLICY_ID, abi.encode(emptyCallers));

        vm.startPrank(WALLET_1);
        vm.expectRevert("Empty callers array");
        policy.onInstall(installData);
        vm.stopPrank();
    }

    function test_WhenInstallingWithCallersArrayContainingZeroAddress() external {
        // it should revert with ZeroAddressCaller
        address[] memory callersWithZero = new address[](2);
        callersWithZero[0] = ALLOWED_CALLER_1;
        callersWithZero[1] = address(0); // Zero address
        bytes memory installData = abi.encodePacked(POLICY_ID, abi.encode(callersWithZero));

        vm.startPrank(WALLET_1);
        vm.expectRevert("Zero address caller");
        policy.onInstall(installData);
        vm.stopPrank();
    }

    function test_WhenInstallingWithValidCallersArray() external {
        // it should set status to Live
        // it should set allowedCaller for each caller
        address[] memory validCallers = new address[](1);
        validCallers[0] = ALLOWED_CALLER_1;
        bytes memory installData = abi.encodePacked(POLICY_ID, abi.encode(validCallers));

        vm.startPrank(WALLET_1);
        policy.onInstall(installData);
        vm.stopPrank();

        // Verify status is Live
        Status statusResult = policy.status(POLICY_ID, WALLET_1);
        assertEq(uint256(statusResult), uint256(Status.Live), "Status should be Live after install");

        // Verify allowedCaller is set
        bool isAllowed = policy.allowedCaller(POLICY_ID, ALLOWED_CALLER_1, WALLET_1);
        assertTrue(isAllowed, "Allowed caller should be registered");
    }

    // ==================== Signature Policy Validation Tests ====================

    function test_WhenCheckingSignaturePolicyWithSenderAsAllowedCaller() external {
        // it should return validation success
        _installPolicyWithCaller(WALLET_1, ALLOWED_CALLER_1);

        bytes32 testHash = keccak256("test_message");

        vm.startPrank(WALLET_1);
        uint256 result = policy.checkSignaturePolicy(POLICY_ID, ALLOWED_CALLER_1, testHash, "");
        vm.stopPrank();

        assertEq(result, 0, "Validation should succeed for allowed caller");
    }

    function test_WhenCheckingSignaturePolicyWithSenderNotAllowed() external {
        // it should return validation failure
        _installPolicyWithCaller(WALLET_1, ALLOWED_CALLER_1);

        bytes32 testHash = keccak256("test_message");

        vm.startPrank(WALLET_1);
        uint256 result = policy.checkSignaturePolicy(POLICY_ID, DISALLOWED_CALLER, testHash, "");
        vm.stopPrank();

        assertEq(result, 1, "Validation should fail for non-allowed caller");
    }

    function test_WhenCheckingSignaturePolicyForNonInstalledAccount() external {
        // it should return validation failure
        // Note: We do NOT install the policy for WALLET_1

        bytes32 testHash = keccak256("test_message");

        vm.startPrank(WALLET_1);
        uint256 result = policy.checkSignaturePolicy(POLICY_ID, ALLOWED_CALLER_1, testHash, "");
        vm.stopPrank();

        assertEq(result, 1, "Validation should fail for non-installed policy");
    }

    function test_WhenMultipleCallersAreConfigured() external {
        // it should allow first caller
        // it should allow second caller
        // it should reject non-configured caller
        address[] memory multipleCallers = new address[](2);
        multipleCallers[0] = ALLOWED_CALLER_1;
        multipleCallers[1] = ALLOWED_CALLER_2;
        bytes memory installData = abi.encodePacked(POLICY_ID, abi.encode(multipleCallers));

        vm.startPrank(WALLET_1);
        policy.onInstall(installData);
        vm.stopPrank();

        bytes32 testHash = keccak256("test_message");

        // Test first caller is allowed
        vm.startPrank(WALLET_1);
        uint256 result1 = policy.checkSignaturePolicy(POLICY_ID, ALLOWED_CALLER_1, testHash, "");
        assertEq(result1, 0, "First caller should be allowed");

        // Test second caller is allowed
        uint256 result2 = policy.checkSignaturePolicy(POLICY_ID, ALLOWED_CALLER_2, testHash, "");
        assertEq(result2, 0, "Second caller should be allowed");

        // Test non-configured caller is rejected
        uint256 result3 = policy.checkSignaturePolicy(POLICY_ID, DISALLOWED_CALLER, testHash, "");
        assertEq(result3, 1, "Non-configured caller should be rejected");
        vm.stopPrank();
    }

    function test_WhenCallerIsAllowedForOneAccountButNotAnother() external {
        // it should pass validation for allowed account
        // it should fail validation for non-allowed account

        // Install policy for WALLET_1 with ALLOWED_CALLER_1
        _installPolicyWithCaller(WALLET_1, ALLOWED_CALLER_1);

        // Install policy for WALLET_2 with ALLOWED_CALLER_2 (different caller)
        address[] memory callers = new address[](1);
        callers[0] = ALLOWED_CALLER_2;
        bytes memory installData = abi.encodePacked(POLICY_ID, abi.encode(callers));

        vm.startPrank(WALLET_2);
        policy.onInstall(installData);
        vm.stopPrank();

        bytes32 testHash = keccak256("test_message");

        // ALLOWED_CALLER_1 should pass for WALLET_1
        vm.startPrank(WALLET_1);
        uint256 result1 = policy.checkSignaturePolicy(POLICY_ID, ALLOWED_CALLER_1, testHash, "");
        assertEq(result1, 0, "ALLOWED_CALLER_1 should pass for WALLET_1");
        vm.stopPrank();

        // ALLOWED_CALLER_1 should fail for WALLET_2 (not allowed for this wallet)
        vm.startPrank(WALLET_2);
        uint256 result2 = policy.checkSignaturePolicy(POLICY_ID, ALLOWED_CALLER_1, testHash, "");
        assertEq(result2, 1, "ALLOWED_CALLER_1 should fail for WALLET_2");
        vm.stopPrank();

        // ALLOWED_CALLER_2 should pass for WALLET_2
        vm.startPrank(WALLET_2);
        uint256 result3 = policy.checkSignaturePolicy(POLICY_ID, ALLOWED_CALLER_2, testHash, "");
        assertEq(result3, 0, "ALLOWED_CALLER_2 should pass for WALLET_2");
        vm.stopPrank();

        // ALLOWED_CALLER_2 should fail for WALLET_1 (not allowed for this wallet)
        vm.startPrank(WALLET_1);
        uint256 result4 = policy.checkSignaturePolicy(POLICY_ID, ALLOWED_CALLER_2, testHash, "");
        assertEq(result4, 1, "ALLOWED_CALLER_2 should fail for WALLET_1");
        vm.stopPrank();
    }

    // ==================== Additional Edge Case Tests ====================

    function test_WhenFirstCallerIsZeroAddress() external {
        // Zero address at the beginning of the array should also revert
        address[] memory callersWithZeroFirst = new address[](2);
        callersWithZeroFirst[0] = address(0); // Zero address first
        callersWithZeroFirst[1] = ALLOWED_CALLER_1;
        bytes memory installData = abi.encodePacked(POLICY_ID, abi.encode(callersWithZeroFirst));

        vm.startPrank(WALLET_1);
        vm.expectRevert("Zero address caller");
        policy.onInstall(installData);
        vm.stopPrank();
    }

    function test_WhenOnlyZeroAddressInArray() external {
        // Single zero address should revert
        address[] memory singleZero = new address[](1);
        singleZero[0] = address(0);
        bytes memory installData = abi.encodePacked(POLICY_ID, abi.encode(singleZero));

        vm.startPrank(WALLET_1);
        vm.expectRevert("Zero address caller");
        policy.onInstall(installData);
        vm.stopPrank();
    }

    // ==================== Helper Functions ====================

    function _installPolicyWithCaller(address wallet, address caller) internal {
        address[] memory callers = new address[](1);
        callers[0] = caller;
        bytes memory installData = abi.encodePacked(POLICY_ID, abi.encode(callers));

        vm.startPrank(wallet);
        policy.onInstall(installData);
        vm.stopPrank();
    }
}
