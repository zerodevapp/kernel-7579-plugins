// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {TimelockPolicy} from "src/policies/TimelockPolicy.sol";

/**
 * @title TimelockSignaturePolicyTest
 * @notice BTT tests for ERC-1271 signature validation with timelock
 * @dev Tests that TimelockPolicy disables ERC-1271 signature validation (always reverts)
 */
contract TimelockSignaturePolicyTest is Test {
    TimelockPolicy public timelockPolicy;

    address constant WALLET = address(0x1234);

    uint48 constant DELAY = 1 days;
    uint48 constant EXPIRATION_PERIOD = 1 days;
    address constant GUARDIAN_ADDR = address(0);

    bytes32 public policyId;
    bytes32 public testHash;

    function setUp() public {
        timelockPolicy = new TimelockPolicy();
        policyId = keccak256(abi.encodePacked("POLICY_ID_1"));
        testHash = keccak256(abi.encodePacked("TEST_HASH_TO_SIGN"));
    }

    /// @notice Helper to install the policy for a wallet
    function _installPolicy(address wallet) internal {
        bytes memory installData = abi.encode(DELAY, EXPIRATION_PERIOD, GUARDIAN_ADDR);
        vm.prank(wallet);
        timelockPolicy.onInstall(abi.encodePacked(policyId, installData));
    }

    // ============================================================
    // Test: checkSignaturePolicy always reverts
    // ============================================================

    function test_WhenCheckingSignaturePolicy() external {
        // it should revert because signature validation is not supported

        // Install policy
        _installPolicy(WALLET);

        // Try to validate a signature - should always revert
        vm.prank(WALLET);
        vm.expectRevert("TimelockPolicy: signature validation not supported");
        timelockPolicy.checkSignaturePolicy(policyId, address(0), testHash, "");
    }

    function test_WhenCheckingSignaturePolicyWithoutInstall() external {
        // it should revert because signature validation is not supported

        // Do NOT install the policy

        // Try to validate a signature - should always revert
        vm.prank(WALLET);
        vm.expectRevert("TimelockPolicy: signature validation not supported");
        timelockPolicy.checkSignaturePolicy(policyId, address(0), testHash, "");
    }

    // ============================================================
    // Test: validateSignatureWithData always reverts
    // ============================================================

    function test_WhenValidatingSignatureWithData() external {
        // it should revert because stateless signature validation is not supported

        bytes memory data = abi.encode(DELAY, EXPIRATION_PERIOD);

        vm.expectRevert("TimelockPolicy: stateless signature validation not supported");
        timelockPolicy.validateSignatureWithData(testHash, "", data);
    }

    // ============================================================
    // Test: validateSignatureWithDataWithSender always reverts
    // ============================================================

    function test_WhenValidatingSignatureWithDataWithSender() external {
        // it should revert because stateless signature validation is not supported

        bytes memory data = abi.encode(DELAY, EXPIRATION_PERIOD);

        vm.expectRevert("TimelockPolicy: stateless signature validation not supported");
        timelockPolicy.validateSignatureWithDataWithSender(WALLET, testHash, "", data);
    }
}
