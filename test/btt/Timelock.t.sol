// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {TimelockPolicy} from "../../src/policies/TimelockPolicy.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC7579Execution} from "openzeppelin-contracts/contracts/interfaces/draft-IERC7579.sol";
import {IAccountExecute} from "account-abstraction/interfaces/IAccountExecute.sol";
import {IModule} from "../../src/interfaces/IERC7579Modules.sol";
import {
    MODULE_TYPE_POLICY,
    MODULE_TYPE_STATELESS_VALIDATOR,
    MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER
} from "../../src/types/Constants.sol";

/**
 * @title TimelockTest
 * @notice BTT tests for TimelockPolicy contract
 */
contract TimelockTest is Test {
    TimelockPolicy public timelockPolicy;

    address public constant WALLET = address(0x1234);
    address public constant ATTACKER = address(0xdead);
    bytes32 public constant POLICY_ID = bytes32(uint256(1));

    uint48 public constant DELAY = 1 hours;
    uint48 public constant EXPIRATION = 1 days;

    uint256 public constant SIG_VALIDATION_FAILED = 1;

    function setUp() public {
        timelockPolicy = new TimelockPolicy();

        // Install policy for WALLET
        bytes memory installData = abi.encode(POLICY_ID, DELAY, EXPIRATION);
        vm.prank(WALLET);
        timelockPolicy.onInstall(installData);
    }

    // ============ Helper Functions ============

    function _createNoopUserOp(address sender, bytes memory signature)
        internal
        pure
        returns (PackedUserOperation memory)
    {
        return PackedUserOperation({
            sender: sender,
            nonce: 0,
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(abi.encodePacked(uint128(100000), uint128(200000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: "",
            signature: signature
        });
    }

    function _createUserOpWithCalldata(address sender, bytes memory callData, uint256 nonce, bytes memory signature)
        internal
        pure
        returns (PackedUserOperation memory)
    {
        return PackedUserOperation({
            sender: sender,
            nonce: nonce,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(100000), uint128(200000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: "",
            signature: signature
        });
    }

    function _createProposalSignature(bytes memory proposalCallData, uint256 proposalNonce)
        internal
        pure
        returns (bytes memory)
    {
        return
            abi.encodePacked(bytes32(proposalCallData.length), proposalCallData, bytes32(proposalNonce), bytes1(0x00));
    }

    function _packValidationData(uint48 validAfter, uint48 validUntil) internal pure returns (uint256) {
        return uint256(validAfter) << 208 | uint256(validUntil) << 160;
    }

    // ============ onInstall Tests ============

    modifier whenCallingOnInstall() {
        _;
    }

    function test_GivenDelayAndExpirationAreValid() external whenCallingOnInstall {
        // it should store the config
        // it should emit TimelockConfigUpdated
        address newWallet = address(0x5555);
        bytes32 newId = bytes32(uint256(2));

        vm.expectEmit(true, true, true, true);
        emit TimelockPolicy.TimelockConfigUpdated(newWallet, newId, 2 hours, 2 days);

        bytes memory installData = abi.encode(newId, uint48(2 hours), uint48(2 days));
        vm.prank(newWallet);
        timelockPolicy.onInstall(installData);

        (uint48 delay, uint48 expiration, bool initialized) = timelockPolicy.timelockConfig(newId, newWallet);
        assertEq(delay, 2 hours, "Delay should be stored");
        assertEq(expiration, 2 days, "Expiration should be stored");
        assertTrue(initialized, "Should be initialized");
    }

    function test_GivenAlreadyInitialized() external whenCallingOnInstall {
        // it should revert with AlreadyInitialized
        bytes memory installData = abi.encode(POLICY_ID, DELAY, EXPIRATION);
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IModule.AlreadyInitialized.selector, WALLET));
        timelockPolicy.onInstall(installData);
    }

    function test_GivenDelayIsZero() external whenCallingOnInstall {
        // it should revert with InvalidDelay
        address newWallet = address(0x6666);
        bytes memory installData = abi.encode(POLICY_ID, uint48(0), EXPIRATION);
        vm.prank(newWallet);
        vm.expectRevert(TimelockPolicy.InvalidDelay.selector);
        timelockPolicy.onInstall(installData);
    }

    function test_GivenExpirationIsZero() external whenCallingOnInstall {
        // it should revert with InvalidExpirationPeriod
        address newWallet = address(0x7777);
        bytes memory installData = abi.encode(POLICY_ID, DELAY, uint48(0));
        vm.prank(newWallet);
        vm.expectRevert(TimelockPolicy.InvalidExpirationPeriod.selector);
        timelockPolicy.onInstall(installData);
    }

    // ============ onUninstall Tests ============

    modifier whenCallingOnUninstall() {
        _;
    }

    function test_GivenInitialized() external whenCallingOnUninstall {
        // it should clear the config
        vm.prank(WALLET);
        timelockPolicy.onUninstall(abi.encode(POLICY_ID));

        (,, bool initialized) = timelockPolicy.timelockConfig(POLICY_ID, WALLET);
        assertFalse(initialized, "Config should be cleared");
    }

    function test_GivenNotInitialized() external whenCallingOnUninstall {
        // it should revert with NotInitialized
        address newWallet = address(0x8888);
        vm.prank(newWallet);
        vm.expectRevert(abi.encodeWithSelector(IModule.NotInitialized.selector, newWallet));
        timelockPolicy.onUninstall(abi.encode(POLICY_ID));
    }

    // ============ isModuleType Tests ============

    modifier whenCallingIsModuleType() {
        _;
    }

    function test_GivenTypeIsPolicy() external whenCallingIsModuleType {
        // it should return true
        assertTrue(timelockPolicy.isModuleType(MODULE_TYPE_POLICY), "Should support policy type");
    }

    function test_GivenTypeIsStatelessValidator() external whenCallingIsModuleType {
        // it should return true
        assertTrue(timelockPolicy.isModuleType(MODULE_TYPE_STATELESS_VALIDATOR), "Should support stateless validator");
    }

    function test_GivenTypeIsStatelessValidatorWithSender() external whenCallingIsModuleType {
        // it should return true
        assertTrue(
            timelockPolicy.isModuleType(MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER),
            "Should support stateless validator with sender"
        );
    }

    function test_GivenTypeIsInvalid() external whenCallingIsModuleType {
        // it should return false
        assertFalse(timelockPolicy.isModuleType(999), "Should not support invalid type");
    }

    // ============ createProposal Tests ============

    modifier whenCallingCreateProposal() {
        _;
    }

    function test_GivenConfigIsInitializedAndProposalDoesNotExist() external whenCallingCreateProposal {
        // it should store the proposal with pending status
        // it should set correct validAfter and validUntil
        // it should emit ProposalCreated
        bytes memory callData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "test");
        uint256 nonce = 100;

        uint256 createTime = block.timestamp;
        bytes32 expectedKey = keccak256(abi.encode(WALLET, keccak256(callData), nonce));

        vm.expectEmit(true, true, true, true);
        emit TimelockPolicy.ProposalCreated(
            WALLET, POLICY_ID, expectedKey, uint48(createTime) + DELAY, uint48(createTime) + DELAY + EXPIRATION
        );

        timelockPolicy.createProposal(POLICY_ID, WALLET, callData, nonce);

        (TimelockPolicy.ProposalStatus status, uint256 validAfter, uint256 validUntil) =
            timelockPolicy.getProposal(WALLET, callData, nonce, POLICY_ID, WALLET);

        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Pending), "Status should be Pending");
        assertEq(validAfter, createTime + DELAY, "validAfter should be timestamp + delay");
        assertEq(validUntil, createTime + DELAY + EXPIRATION, "validUntil should be validAfter + expiration");
    }

    function test_GivenNotInitialized_WhenCallingCreateProposal() external whenCallingCreateProposal {
        // it should revert with NotInitialized
        address uninitWallet = address(0x9999);
        bytes memory callData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "test");

        vm.expectRevert(abi.encodeWithSelector(IModule.NotInitialized.selector, uninitWallet));
        timelockPolicy.createProposal(POLICY_ID, uninitWallet, callData, 0);
    }

    function test_GivenProposalAlreadyExists() external whenCallingCreateProposal {
        // it should revert with ProposalAlreadyExists
        bytes memory callData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "test");
        uint256 nonce = 200;

        timelockPolicy.createProposal(POLICY_ID, WALLET, callData, nonce);

        vm.expectRevert(TimelockPolicy.ProposalAlreadyExists.selector);
        timelockPolicy.createProposal(POLICY_ID, WALLET, callData, nonce);
    }

    // ============ cancelProposal Tests ============

    modifier whenCallingCancelProposal() {
        _;
    }

    function test_GivenCallerIsAccountAndProposalIsPending() external whenCallingCancelProposal {
        // it should set status to cancelled
        // it should emit ProposalCancelled
        bytes memory callData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "test");
        uint256 nonce = 300;

        timelockPolicy.createProposal(POLICY_ID, WALLET, callData, nonce);

        bytes32 expectedKey = keccak256(abi.encode(WALLET, keccak256(callData), nonce));

        vm.expectEmit(true, true, true, true);
        emit TimelockPolicy.ProposalCancelled(WALLET, POLICY_ID, expectedKey);

        vm.prank(WALLET);
        timelockPolicy.cancelProposal(POLICY_ID, WALLET, callData, nonce);

        (TimelockPolicy.ProposalStatus status,,) =
            timelockPolicy.getProposal(WALLET, callData, nonce, POLICY_ID, WALLET);
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Cancelled), "Status should be Cancelled");
    }

    function test_GivenCallerIsNotAccount() external whenCallingCancelProposal {
        // it should revert with OnlyAccount
        bytes memory callData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "test");
        uint256 nonce = 400;

        timelockPolicy.createProposal(POLICY_ID, WALLET, callData, nonce);

        vm.prank(ATTACKER);
        vm.expectRevert(TimelockPolicy.OnlyAccount.selector);
        timelockPolicy.cancelProposal(POLICY_ID, WALLET, callData, nonce);
    }

    function test_GivenNotInitialized_WhenCallingCancelProposal() external whenCallingCancelProposal {
        // it should revert with NotInitialized
        address uninitWallet = address(0xaaaa);
        bytes memory callData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "test");

        vm.prank(uninitWallet);
        vm.expectRevert(abi.encodeWithSelector(IModule.NotInitialized.selector, uninitWallet));
        timelockPolicy.cancelProposal(POLICY_ID, uninitWallet, callData, 0);
    }

    function test_GivenProposalDoesNotExist() external whenCallingCancelProposal {
        // it should revert with ProposalNotPending
        bytes memory callData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "test");
        uint256 nonce = 500;

        vm.prank(WALLET);
        vm.expectRevert(TimelockPolicy.ProposalNotPending.selector);
        timelockPolicy.cancelProposal(POLICY_ID, WALLET, callData, nonce);
    }

    function test_GivenProposalIsAlreadyCancelled() external whenCallingCancelProposal {
        // it should revert with ProposalNotPending
        bytes memory callData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "test");
        uint256 nonce = 600;

        timelockPolicy.createProposal(POLICY_ID, WALLET, callData, nonce);

        vm.prank(WALLET);
        timelockPolicy.cancelProposal(POLICY_ID, WALLET, callData, nonce);

        vm.prank(WALLET);
        vm.expectRevert(TimelockPolicy.ProposalNotPending.selector);
        timelockPolicy.cancelProposal(POLICY_ID, WALLET, callData, nonce);
    }

    // ============ checkUserOpPolicy - Proposal Creation Tests ============

    modifier whenCallingCheckUserOpPolicyToCreateProposal() {
        _;
    }

    function test_GivenNoopCalldataAndValidSignature() external whenCallingCheckUserOpPolicyToCreateProposal {
        // it should create the proposal
        // it should return zero for state persistence
        // it should emit ProposalCreated
        bytes memory proposalCallData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "test");
        uint256 proposalNonce = 700;
        bytes memory sig = _createProposalSignature(proposalCallData, proposalNonce);

        PackedUserOperation memory userOp = _createNoopUserOp(WALLET, sig);

        bytes32 expectedKey = keccak256(abi.encode(WALLET, keccak256(proposalCallData), proposalNonce));

        vm.expectEmit(true, true, true, true);
        emit TimelockPolicy.ProposalCreated(
            WALLET,
            POLICY_ID,
            expectedKey,
            uint48(block.timestamp) + DELAY,
            uint48(block.timestamp) + DELAY + EXPIRATION
        );

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        // Proposal creation must return 0 for state persistence
        assertEq(result, 0, "Should return 0 for state persistence");

        (TimelockPolicy.ProposalStatus status,,) =
            timelockPolicy.getProposal(WALLET, proposalCallData, proposalNonce, POLICY_ID, WALLET);
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Pending), "Proposal should be created");
    }

    function test_GivenNoopCalldataAndSignatureShorterThan65Bytes()
        external
        whenCallingCheckUserOpPolicyToCreateProposal
    {
        // it should return SIG_VALIDATION_FAILED
        bytes memory shortSig = new bytes(64);
        PackedUserOperation memory userOp = _createNoopUserOp(WALLET, shortSig);

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        assertEq(result, SIG_VALIDATION_FAILED, "Should fail with short signature");
    }

    function test_GivenNoopCalldataAndSignatureClaimsMoreDataThanAvailable()
        external
        whenCallingCheckUserOpPolicyToCreateProposal
    {
        // it should return SIG_VALIDATION_FAILED
        bytes memory badSig = abi.encodePacked(
            bytes32(uint256(1000)), // claims 1000 bytes of calldata
            bytes32(0), // nonce
            bytes1(0x00) // only 65 bytes total, not enough for claimed calldata
        );

        PackedUserOperation memory userOp = _createNoopUserOp(WALLET, badSig);

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        assertEq(result, SIG_VALIDATION_FAILED, "Should fail when signature claims more data than available");
    }

    function test_GivenNoopCalldataAndProposalAlreadyExists() external whenCallingCheckUserOpPolicyToCreateProposal {
        // it should return SIG_VALIDATION_FAILED
        bytes memory proposalCallData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "test");
        uint256 proposalNonce = 800;
        bytes memory sig = _createProposalSignature(proposalCallData, proposalNonce);

        PackedUserOperation memory userOp = _createNoopUserOp(WALLET, sig);

        // First creation should succeed
        vm.prank(WALLET);
        timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        // Second creation should fail
        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        assertEq(result, SIG_VALIDATION_FAILED, "Should fail for duplicate proposal");
    }

    // ============ checkUserOpPolicy - Proposal Execution Tests ============

    modifier whenCallingCheckUserOpPolicyToExecuteProposal() {
        _;
    }

    function test_GivenProposalIsPendingAndTimelockPassed() external whenCallingCheckUserOpPolicyToExecuteProposal {
        // it should mark proposal as executed
        // it should return packed validation data with timing
        // it should emit ProposalExecuted
        bytes memory proposalCallData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "action");
        uint256 proposalNonce = 900;

        uint256 createTime = block.timestamp;
        timelockPolicy.createProposal(POLICY_ID, WALLET, proposalCallData, proposalNonce);

        // Get the actual stored proposal values
        (, uint256 storedValidAfter, uint256 storedValidUntil) =
            timelockPolicy.getProposal(WALLET, proposalCallData, proposalNonce, POLICY_ID, WALLET);

        vm.warp(block.timestamp + DELAY + 1);

        PackedUserOperation memory executeOp = _createUserOpWithCalldata(WALLET, proposalCallData, proposalNonce, "");

        bytes32 expectedKey = keccak256(abi.encode(WALLET, keccak256(proposalCallData), proposalNonce));

        vm.expectEmit(true, true, true, true);
        emit TimelockPolicy.ProposalExecuted(WALLET, POLICY_ID, expectedKey);

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, executeOp);

        // Extract validAfter and validUntil from packed data
        uint48 validAfter = uint48(result >> 208);
        uint48 validUntil = uint48(result >> 160);
        assertEq(validAfter, storedValidAfter, "validAfter should match proposal");
        assertEq(validUntil, storedValidUntil, "validUntil should match proposal");

        (TimelockPolicy.ProposalStatus status,,) =
            timelockPolicy.getProposal(WALLET, proposalCallData, proposalNonce, POLICY_ID, WALLET);
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Executed), "Proposal should be executed");
    }

    function test_GivenNoProposalExists() external whenCallingCheckUserOpPolicyToExecuteProposal {
        // it should return SIG_VALIDATION_FAILED
        bytes memory callData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "attack");
        PackedUserOperation memory userOp = _createUserOpWithCalldata(WALLET, callData, 0, "");

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        assertEq(result, SIG_VALIDATION_FAILED, "Should fail without proposal");
    }

    function test_GivenProposalIsCancelled() external whenCallingCheckUserOpPolicyToExecuteProposal {
        // it should return SIG_VALIDATION_FAILED
        bytes memory callData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "test");
        uint256 nonce = 1000;

        timelockPolicy.createProposal(POLICY_ID, WALLET, callData, nonce);

        vm.prank(WALLET);
        timelockPolicy.cancelProposal(POLICY_ID, WALLET, callData, nonce);

        PackedUserOperation memory userOp = _createUserOpWithCalldata(WALLET, callData, nonce, "");

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        assertEq(result, SIG_VALIDATION_FAILED, "Should fail for cancelled proposal");
    }

    function test_GivenProposalIsAlreadyExecuted() external whenCallingCheckUserOpPolicyToExecuteProposal {
        // it should return SIG_VALIDATION_FAILED
        bytes memory callData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "test");
        uint256 nonce = 1100;

        timelockPolicy.createProposal(POLICY_ID, WALLET, callData, nonce);

        vm.warp(block.timestamp + DELAY + 1);

        PackedUserOperation memory userOp = _createUserOpWithCalldata(WALLET, callData, nonce, "");

        // First execution
        vm.prank(WALLET);
        timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        // Second execution attempt
        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        assertEq(result, SIG_VALIDATION_FAILED, "Should fail for already executed proposal");
    }

    // ============ checkUserOpPolicy - Not Initialized ============

    function test_WhenCallingCheckUserOpPolicyWithoutInitialization() external {
        // it should return SIG_VALIDATION_FAILED
        address uninitWallet = address(0xbbbb);
        bytes memory sig = _createProposalSignature("test", 0);
        PackedUserOperation memory userOp = _createNoopUserOp(uninitWallet, sig);

        vm.prank(uninitWallet);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        assertEq(result, SIG_VALIDATION_FAILED, "Should fail when not initialized");
    }

    // ============ checkSignaturePolicy Tests ============

    modifier whenCallingCheckSignaturePolicy() {
        _;
    }

    function test_GivenInitialized_WhenCallingCheckSignaturePolicy() external whenCallingCheckSignaturePolicy {
        // it should return zero
        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkSignaturePolicy(POLICY_ID, address(0), bytes32(0), "");
        assertEq(result, 0, "Should return 0 when initialized");
    }

    function test_GivenNotInitialized_WhenCallingCheckSignaturePolicy() external whenCallingCheckSignaturePolicy {
        // it should return one
        address uninitWallet = address(0xcccc);
        vm.prank(uninitWallet);
        uint256 result = timelockPolicy.checkSignaturePolicy(POLICY_ID, address(0), bytes32(0), "");
        assertEq(result, 1, "Should return 1 when not initialized");
    }

    // ============ validateSignatureWithData Tests ============

    modifier whenCallingValidateSignatureWithData() {
        _;
    }

    function test_GivenDelayAndExpirationAreNonzero() external whenCallingValidateSignatureWithData {
        // it should return true
        bytes memory data = abi.encode(uint48(1 hours), uint48(1 days));
        bool result = timelockPolicy.validateSignatureWithData(bytes32(0), "", data);
        assertTrue(result, "Should return true for valid data");
    }

    function test_GivenDelayIsZero_WhenCallingValidateSignatureWithData()
        external
        whenCallingValidateSignatureWithData
    {
        // it should return false
        bytes memory data = abi.encode(uint48(0), uint48(1 days));
        bool result = timelockPolicy.validateSignatureWithData(bytes32(0), "", data);
        assertFalse(result, "Should return false for zero delay");
    }

    function test_GivenExpirationIsZero_WhenCallingValidateSignatureWithData()
        external
        whenCallingValidateSignatureWithData
    {
        // it should return false
        bytes memory data = abi.encode(uint48(1 hours), uint48(0));
        bool result = timelockPolicy.validateSignatureWithData(bytes32(0), "", data);
        assertFalse(result, "Should return false for zero expiration");
    }

    // ============ validateSignatureWithDataWithSender Tests ============

    modifier whenCallingValidateSignatureWithDataWithSender() {
        _;
    }

    function test_GivenDelayAndExpirationAreNonzero_WhenCallingValidateSignatureWithDataWithSender()
        external
        whenCallingValidateSignatureWithDataWithSender
    {
        // it should return true
        bytes memory data = abi.encode(uint48(1 hours), uint48(1 days));
        bool result = timelockPolicy.validateSignatureWithDataWithSender(address(0), bytes32(0), "", data);
        assertTrue(result, "Should return true for valid data");
    }

    function test_GivenDelayIsZero_WhenCallingValidateSignatureWithDataWithSender()
        external
        whenCallingValidateSignatureWithDataWithSender
    {
        // it should return false
        bytes memory data = abi.encode(uint48(0), uint48(1 days));
        bool result = timelockPolicy.validateSignatureWithDataWithSender(address(0), bytes32(0), "", data);
        assertFalse(result, "Should return false for zero delay");
    }

    function test_GivenExpirationIsZero_WhenCallingValidateSignatureWithDataWithSender()
        external
        whenCallingValidateSignatureWithDataWithSender
    {
        // it should return false
        bytes memory data = abi.encode(uint48(1 hours), uint48(0));
        bool result = timelockPolicy.validateSignatureWithDataWithSender(address(0), bytes32(0), "", data);
        assertFalse(result, "Should return false for zero expiration");
    }

    // ============ getProposal Tests ============

    modifier whenCallingGetProposal() {
        _;
    }

    function test_GivenProposalExists() external whenCallingGetProposal {
        // it should return status validAfter and validUntil
        bytes memory callData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "test");
        uint256 nonce = 1200;

        uint256 createTime = block.timestamp;
        timelockPolicy.createProposal(POLICY_ID, WALLET, callData, nonce);

        (TimelockPolicy.ProposalStatus status, uint256 validAfter, uint256 validUntil) =
            timelockPolicy.getProposal(WALLET, callData, nonce, POLICY_ID, WALLET);

        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Pending), "Status should be Pending");
        assertEq(validAfter, createTime + DELAY, "validAfter should be correct");
        assertEq(validUntil, createTime + DELAY + EXPIRATION, "validUntil should be correct");
    }

    function test_GivenProposalDoesNotExist_WhenCallingGetProposal() external whenCallingGetProposal {
        // it should return None status and zeros
        bytes memory callData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "test");

        (TimelockPolicy.ProposalStatus status, uint256 validAfter, uint256 validUntil) =
            timelockPolicy.getProposal(WALLET, callData, 9999, POLICY_ID, WALLET);

        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.None), "Status should be None");
        assertEq(validAfter, 0, "validAfter should be 0");
        assertEq(validUntil, 0, "validUntil should be 0");
    }

    // ============ computeUserOpKey Tests ============

    function test_WhenCallingComputeUserOpKey() external {
        // it should match manual keccak256 computation
        bytes memory callData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "test");
        uint256 nonce = 1300;

        bytes32 expected = keccak256(abi.encode(WALLET, keccak256(callData), nonce));
        bytes32 result = timelockPolicy.computeUserOpKey(WALLET, callData, nonce);

        assertEq(result, expected, "computeUserOpKey should match manual computation");
    }

    // ============ _isNoOpCalldata Tests ============

    modifier whenDetectingNoopCalldata() {
        _;
    }

    function test_GivenCalldataIsEmpty() external whenDetectingNoopCalldata {
        // it should be detected as noop
        bytes memory sig = _createProposalSignature("test", 0);
        PackedUserOperation memory userOp = _createNoopUserOp(WALLET, sig);

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        // If it's a no-op, it goes to creation path and returns 0
        assertEq(result, 0, "Empty calldata should be detected as noop");
    }

    function test_GivenCalldataIsShorterThan4Bytes() external whenDetectingNoopCalldata {
        // it should not be detected as noop
        bytes memory shortCalldata = hex"aabb";
        PackedUserOperation memory userOp = _createUserOpWithCalldata(WALLET, shortCalldata, 0, "");

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        // Not a no-op, goes to execution path, no proposal exists
        assertEq(result, SIG_VALIDATION_FAILED, "Short calldata should not be noop");
    }

    function test_GivenSelectorIsUnrecognized() external whenDetectingNoopCalldata {
        // it should not be detected as noop
        bytes memory unknownCalldata = abi.encodeWithSelector(bytes4(0xdeadbeef), "test");
        PackedUserOperation memory userOp = _createUserOpWithCalldata(WALLET, unknownCalldata, 0, "");

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        assertEq(result, SIG_VALIDATION_FAILED, "Unknown selector should not be noop");
    }

    // ============ _isNoOpERC7579Execute Tests ============

    modifier whenDetectingERC7579ExecuteNoop() {
        _;
    }

    function test_GivenTargetIsSelfAndValueIsZeroAndInnerCalldataIsEmpty() external whenDetectingERC7579ExecuteNoop {
        // it should be detected as noop
        bytes memory callData = abi.encodePacked(
            IERC7579Execution.execute.selector,
            bytes32(0), // mode
            bytes32(uint256(32)), // offset
            bytes32(uint256(84)), // execDataLength (20+32+32)
            bytes20(WALLET), // target = self
            bytes32(uint256(0)), // value = 0
            bytes32(uint256(0)) // innerCalldataLength = 0
        );

        bytes memory sig = _createProposalSignature("proposal", 0);
        PackedUserOperation memory userOp = _createUserOpWithCalldata(WALLET, callData, 0, sig);

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        assertEq(result, 0, "ERC7579 execute to self with zero value should be noop");
    }

    function test_GivenTargetIsZeroAddressAndValueIsZeroAndInnerCalldataIsEmpty()
        external
        whenDetectingERC7579ExecuteNoop
    {
        // it should be detected as noop
        bytes memory callData = abi.encodePacked(
            IERC7579Execution.execute.selector,
            bytes32(0), // mode
            bytes32(uint256(32)), // offset
            bytes32(uint256(84)), // execDataLength
            bytes20(address(0)), // target = address(0)
            bytes32(uint256(0)), // value = 0
            bytes32(uint256(0)) // innerCalldataLength = 0
        );

        bytes memory sig = _createProposalSignature("proposal", 1);
        PackedUserOperation memory userOp = _createUserOpWithCalldata(WALLET, callData, 0, sig);

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        assertEq(result, 0, "ERC7579 execute to zero address with zero value should be noop");
    }

    function test_GivenCalldataIsShorterThan68Bytes() external whenDetectingERC7579ExecuteNoop {
        // it should not be detected as noop
        bytes memory shortCallData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0));

        PackedUserOperation memory userOp = _createUserOpWithCalldata(WALLET, shortCallData, 0, "");

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        assertEq(result, SIG_VALIDATION_FAILED, "Too short for offset should not be noop");
    }

    function test_GivenOffsetIsNot32() external whenDetectingERC7579ExecuteNoop {
        // it should not be detected as noop
        bytes memory callData = abi.encodePacked(
            IERC7579Execution.execute.selector,
            bytes32(0), // mode
            bytes32(uint256(64)), // wrong offset (should be 32)
            bytes32(uint256(52)), // length
            WALLET,
            uint256(0),
            uint256(0)
        );

        PackedUserOperation memory userOp = _createUserOpWithCalldata(WALLET, callData, 0, "");

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        assertEq(result, SIG_VALIDATION_FAILED, "Wrong offset should not be noop");
    }

    function test_GivenCalldataIsShorterThan100Bytes() external whenDetectingERC7579ExecuteNoop {
        // it should not be detected as noop
        bytes memory callData = abi.encodePacked(
            IERC7579Execution.execute.selector,
            bytes32(0), // mode
            bytes32(uint256(32)) // offset
            // missing length and data
        );

        PackedUserOperation memory userOp = _createUserOpWithCalldata(WALLET, callData, 0, "");

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        assertEq(result, SIG_VALIDATION_FAILED, "Too short for length should not be noop");
    }

    function test_GivenExecDataLengthIsLessThan52() external whenDetectingERC7579ExecuteNoop {
        // it should not be detected as noop
        bytes memory callData = abi.encodePacked(
            IERC7579Execution.execute.selector,
            bytes32(0), // mode
            bytes32(uint256(32)), // offset
            bytes32(uint256(20)) // length only 20 (need at least 52)
        );

        PackedUserOperation memory userOp = _createUserOpWithCalldata(WALLET, callData, 0, "");

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        assertEq(result, SIG_VALIDATION_FAILED, "Exec data too short should not be noop");
    }

    function test_GivenTargetIsNotSelfOrZero() external whenDetectingERC7579ExecuteNoop {
        // it should not be detected as noop
        bytes memory executionCalldata = abi.encodePacked(ATTACKER, uint256(0), uint256(0));

        bytes memory callData =
            abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), executionCalldata);

        PackedUserOperation memory userOp = _createUserOpWithCalldata(WALLET, callData, 0, "");

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        assertEq(result, SIG_VALIDATION_FAILED, "Wrong target should not be noop");
    }

    function test_GivenValueIsNonzero() external whenDetectingERC7579ExecuteNoop {
        // it should not be detected as noop
        bytes memory executionCalldata = abi.encodePacked(WALLET, uint256(1 ether), uint256(0));

        bytes memory callData =
            abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), executionCalldata);

        PackedUserOperation memory userOp = _createUserOpWithCalldata(WALLET, callData, 0, "");

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        assertEq(result, SIG_VALIDATION_FAILED, "Non-zero value should not be noop");
    }

    function test_GivenCalldataIsShorterThan184Bytes() external whenDetectingERC7579ExecuteNoop {
        // it should not be detected as noop
        bytes memory callData = abi.encodePacked(
            IERC7579Execution.execute.selector,
            bytes32(0), // mode
            bytes32(uint256(32)), // offset
            bytes32(uint256(52)), // execDataLength (exactly 52, no room for inner calldata length)
            WALLET, // 20 bytes
            uint256(0) // 32 bytes = 52 total
        );

        PackedUserOperation memory userOp = _createUserOpWithCalldata(WALLET, callData, 0, "");

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        assertEq(result, SIG_VALIDATION_FAILED, "Too short for inner calldata length should not be noop");
    }

    function test_GivenInnerCalldataLengthIsNonzero() external whenDetectingERC7579ExecuteNoop {
        // it should not be detected as noop
        bytes memory executionCalldata = abi.encodePacked(WALLET, uint256(0), uint256(10));

        bytes memory callData =
            abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), executionCalldata);

        PackedUserOperation memory userOp = _createUserOpWithCalldata(WALLET, callData, 0, "");

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        assertEq(result, SIG_VALIDATION_FAILED, "Non-empty inner calldata should not be noop");
    }

    // ============ _isNoOpExecuteUserOp Tests ============

    modifier whenDetectingExecuteUserOpNoop() {
        _;
    }

    function test_GivenUserOpDataIsEmpty() external whenDetectingExecuteUserOpNoop {
        // it should be detected as noop
        bytes memory callData = abi.encodePacked(
            IAccountExecute.executeUserOp.selector,
            bytes32(uint256(32)), // offset to userOp
            bytes32(0), // userOpHash
            bytes32(uint256(0)) // userOp length = 0
        );

        bytes memory sig = _createProposalSignature("proposal", 2);
        PackedUserOperation memory userOp = _createUserOpWithCalldata(WALLET, callData, 0, sig);

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        assertEq(result, 0, "executeUserOp with empty userOp should be noop");
    }

    function test_GivenCalldataIsShorterThan100Bytes_WhenDetectingExecuteUserOpNoop()
        external
        whenDetectingExecuteUserOpNoop
    {
        // it should not be detected as noop
        bytes memory callData = abi.encodePacked(IAccountExecute.executeUserOp.selector, bytes32(uint256(32)));

        PackedUserOperation memory userOp = _createUserOpWithCalldata(WALLET, callData, 0, "");

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        assertEq(result, SIG_VALIDATION_FAILED, "Too short executeUserOp should not be noop");
    }

    function test_GivenOffsetIsNot32_WhenDetectingExecuteUserOpNoop() external whenDetectingExecuteUserOpNoop {
        // it should not be detected as noop
        bytes memory callData = abi.encodePacked(
            IAccountExecute.executeUserOp.selector,
            bytes32(uint256(64)), // wrong offset
            bytes32(0),
            bytes32(uint256(0))
        );

        PackedUserOperation memory userOp = _createUserOpWithCalldata(WALLET, callData, 0, "");

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        assertEq(result, SIG_VALIDATION_FAILED, "Wrong offset in executeUserOp should not be noop");
    }

    function test_GivenUserOpLengthIsNonzero() external whenDetectingExecuteUserOpNoop {
        // it should not be detected as noop
        bytes memory callData = abi.encodePacked(
            IAccountExecute.executeUserOp.selector,
            bytes32(uint256(32)),
            bytes32(0),
            bytes32(uint256(10)) // non-empty userOp
        );

        PackedUserOperation memory userOp = _createUserOpWithCalldata(WALLET, callData, 0, "");

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        assertEq(result, SIG_VALIDATION_FAILED, "Non-empty userOp should not be noop");
    }

    // ============ _packValidationData Tests ============

    function test_WhenPackingValidationData() external {
        // it should correctly pack validAfter and validUntil
        // Test the packing by creating a proposal and checking the returned validation data
        bytes memory callData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "test");
        uint256 nonce = 1400;

        timelockPolicy.createProposal(POLICY_ID, WALLET, callData, nonce);

        // Get the actual stored proposal values
        (, uint256 storedValidAfter, uint256 storedValidUntil) =
            timelockPolicy.getProposal(WALLET, callData, nonce, POLICY_ID, WALLET);

        vm.warp(block.timestamp + DELAY + 1);

        PackedUserOperation memory userOp = _createUserOpWithCalldata(WALLET, callData, nonce, "");

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        uint256 expectedPacked = _packValidationData(uint48(storedValidAfter), uint48(storedValidUntil));

        assertEq(result, expectedPacked, "Packed validation data should match expected");
    }

    // ============ Security Tests ============

    modifier whenTestingSecurityScenarios() {
        _;
    }

    function test_GivenAttackerTriesToExecuteWithoutProposal() external whenTestingSecurityScenarios {
        // it should return SIG_VALIDATION_FAILED
        bytes memory maliciousCalldata =
            abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "steal_funds");

        PackedUserOperation memory attackOp = _createUserOpWithCalldata(WALLET, maliciousCalldata, 0, "");

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, attackOp);

        assertEq(result, SIG_VALIDATION_FAILED, "Attack without proposal should fail");
    }

    function test_GivenAttackerTriesToExecuteImmediatelyAfterCreation() external whenTestingSecurityScenarios {
        // it should return packed data with future validAfter
        bytes memory callData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "action");
        uint256 nonce = 1500;

        uint256 createTime = block.timestamp;
        timelockPolicy.createProposal(POLICY_ID, WALLET, callData, nonce);

        // Try to execute immediately (before timelock)
        PackedUserOperation memory executeOp = _createUserOpWithCalldata(WALLET, callData, nonce, "");

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, executeOp);

        // Extract validAfter - it should be in the future
        uint48 validAfter = uint48(result >> 208);
        assertGt(validAfter, block.timestamp, "validAfter should be in the future");
        assertEq(validAfter, uint48(createTime) + DELAY, "validAfter should be createTime + DELAY");
    }

    function test_GivenAttackerTriesToReexecuteAUsedProposal() external whenTestingSecurityScenarios {
        // it should return SIG_VALIDATION_FAILED
        bytes memory callData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "action");
        uint256 nonce = 1600;

        timelockPolicy.createProposal(POLICY_ID, WALLET, callData, nonce);

        vm.warp(block.timestamp + DELAY + 1);

        PackedUserOperation memory executeOp = _createUserOpWithCalldata(WALLET, callData, nonce, "");

        // First execution - should succeed
        vm.prank(WALLET);
        uint256 firstResult = timelockPolicy.checkUserOpPolicy(POLICY_ID, executeOp);
        assertNotEq(firstResult, SIG_VALIDATION_FAILED, "First execution should succeed");

        // Verify proposal is marked as executed
        (TimelockPolicy.ProposalStatus status,,) =
            timelockPolicy.getProposal(WALLET, callData, nonce, POLICY_ID, WALLET);
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Executed), "Should be executed");

        // Second execution attempt - should fail
        vm.prank(WALLET);
        uint256 secondResult = timelockPolicy.checkUserOpPolicy(POLICY_ID, executeOp);
        assertEq(secondResult, SIG_VALIDATION_FAILED, "Re-execution should fail");
    }

    function test_GivenProposalCreationReturnsZero() external whenTestingSecurityScenarios {
        // it should allow state to persist via EntryPoint
        bytes memory proposalCallData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "test");
        uint256 proposalNonce = 1700;
        bytes memory sig = _createProposalSignature(proposalCallData, proposalNonce);

        PackedUserOperation memory userOp = _createNoopUserOp(WALLET, sig);

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        // Result must be 0 for EntryPoint to not revert
        assertEq(result, 0, "Proposal creation must return 0 for state persistence");

        // Verify the proposal was actually created and persisted
        (TimelockPolicy.ProposalStatus status, uint256 validAfter, uint256 validUntil) =
            timelockPolicy.getProposal(WALLET, proposalCallData, proposalNonce, POLICY_ID, WALLET);

        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Pending), "Proposal state should persist");
        assertGt(validAfter, 0, "validAfter should be set");
        assertGt(validUntil, validAfter, "validUntil should be after validAfter");
    }

    function test_GivenAttackerTriesToCancelAnotherAccountsProposal() external whenTestingSecurityScenarios {
        // it should revert with OnlyAccount
        bytes memory callData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "test");
        uint256 nonce = 1800;

        timelockPolicy.createProposal(POLICY_ID, WALLET, callData, nonce);

        vm.prank(ATTACKER);
        vm.expectRevert(TimelockPolicy.OnlyAccount.selector);
        timelockPolicy.cancelProposal(POLICY_ID, WALLET, callData, nonce);

        // Verify proposal is still pending
        (TimelockPolicy.ProposalStatus status,,) =
            timelockPolicy.getProposal(WALLET, callData, nonce, POLICY_ID, WALLET);
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Pending), "Proposal should still be pending");
    }
}
