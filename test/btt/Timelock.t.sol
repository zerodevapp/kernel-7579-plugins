// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {TimelockPolicy} from "../../src/policies/TimelockPolicy.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC7579Execution} from "openzeppelin-contracts/contracts/interfaces/draft-IERC7579.sol";
import {IAccountExecute} from "account-abstraction/interfaces/IAccountExecute.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";
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
    address public constant GUARDIAN = address(0);

    uint256 public constant SIG_VALIDATION_FAILED = 1;

    function setUp() public {
        timelockPolicy = new TimelockPolicy();

        // Install policy for WALLET
        bytes memory installData = abi.encode(POLICY_ID, DELAY, EXPIRATION, GUARDIAN);
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

        address newGuardian = address(0x9999);

        vm.expectEmit(true, true, true, true);
        emit TimelockPolicy.TimelockConfigUpdated(newWallet, newId, 2 hours, 2 days, newGuardian);

        bytes memory installData = abi.encode(newId, uint48(2 hours), uint48(2 days), newGuardian);
        vm.prank(newWallet);
        timelockPolicy.onInstall(installData);

        (uint48 delay, uint48 expiration, address guardian_, bool initialized) =
            timelockPolicy.timelockConfig(newId, newWallet);
        assertEq(delay, 2 hours, "Delay should be stored");
        assertEq(expiration, 2 days, "Expiration should be stored");
        assertEq(guardian_, newGuardian, "Guardian should be stored");
        assertTrue(initialized, "Should be initialized");
    }

    function test_GivenAlreadyInitialized() external whenCallingOnInstall {
        // it should revert with AlreadyInitialized
        bytes memory installData = abi.encode(POLICY_ID, DELAY, EXPIRATION, GUARDIAN);
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IModule.AlreadyInitialized.selector, WALLET));
        timelockPolicy.onInstall(installData);
    }

    function test_GivenDelayIsZero() external whenCallingOnInstall {
        // it should revert with InvalidDelay
        address newWallet = address(0x6666);
        bytes memory installData = abi.encode(POLICY_ID, uint48(0), EXPIRATION, GUARDIAN);
        vm.prank(newWallet);
        vm.expectRevert(TimelockPolicy.InvalidDelay.selector);
        timelockPolicy.onInstall(installData);
    }

    function test_GivenExpirationIsZero() external whenCallingOnInstall {
        // it should revert with InvalidExpirationPeriod
        address newWallet = address(0x7777);
        bytes memory installData = abi.encode(POLICY_ID, DELAY, uint48(0), GUARDIAN);
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

        (,,, bool initialized) = timelockPolicy.timelockConfig(POLICY_ID, WALLET);

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

    // ============ cancelProposal Tests ============

    modifier whenCallingCancelProposal() {
        _;
    }

    function test_GivenCallerIsAccountAndProposalIsPending() external whenCallingCancelProposal {
        // it should set status to cancelled (cancelling a Pending proposal)
        // it should emit ProposalCancelled
        bytes memory callData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "test");
        uint256 nonce = 301;

        // Create proposal via no-op UserOp to get Pending status
        bytes memory sig = _createProposalSignature(callData, nonce);
        PackedUserOperation memory userOp = _createNoopUserOp(WALLET, sig);
        vm.prank(WALLET);
        timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

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

        // Create proposal via no-op UserOp
        bytes memory sig = _createProposalSignature(callData, nonce);
        PackedUserOperation memory noopOp = _createNoopUserOp(WALLET, sig);
        vm.prank(WALLET);
        timelockPolicy.checkUserOpPolicy(POLICY_ID, noopOp);

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

        // Create proposal via no-op UserOp
        bytes memory sig = _createProposalSignature(callData, nonce);
        PackedUserOperation memory noopOp = _createNoopUserOp(WALLET, sig);
        vm.prank(WALLET);
        timelockPolicy.checkUserOpPolicy(POLICY_ID, noopOp);

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
        // it should create the proposal as Pending with clock started
        // it should return zero for state persistence
        // it should emit ProposalCreated with timing
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
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Pending), "Proposal should be Pending");
    }

    function test_GivenNoopCalldataAndSignature64BytesWithZeroCallDataLength()
        external
        whenCallingCheckUserOpPolicyToCreateProposal
    {
        // A 64-byte all-zeros signature decodes as callDataLength=0, proposalNonce=0.
        // This passes the length check (sig.length >= 64 + 0) and creates a valid
        // proposal with empty calldata and nonce 0.
        bytes memory shortSig = new bytes(64);
        PackedUserOperation memory userOp = _createNoopUserOp(WALLET, shortSig);

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        // Returns 0 (proposal created successfully) not SIG_VALIDATION_FAILED
        assertEq(result, 0, "64-byte sig with zero callDataLength creates a valid proposal");
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

    function test_GivenNoopCalldataAndProposalAlreadyPending() external whenCallingCheckUserOpPolicyToCreateProposal {
        // it should return SIG_VALIDATION_FAILED when proposal is already Pending
        bytes memory proposalCallData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "test");
        uint256 proposalNonce = 800;
        bytes memory sig = _createProposalSignature(proposalCallData, proposalNonce);

        PackedUserOperation memory userOp = _createNoopUserOp(WALLET, sig);

        // First call: create -> Pending
        vm.prank(WALLET);
        timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        // Second call: already Pending -> should fail
        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        assertEq(result, SIG_VALIDATION_FAILED, "Should fail for already Pending proposal");
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

        // Create proposal via no-op UserOp (creates Pending directly)
        bytes memory sig = _createProposalSignature(proposalCallData, proposalNonce);
        PackedUserOperation memory noopOp = _createNoopUserOp(WALLET, sig);
        vm.prank(WALLET);
        timelockPolicy.checkUserOpPolicy(POLICY_ID, noopOp);

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
        assertEq(validAfter, storedValidAfter, "validAfter in packed data should match proposal validAfter");
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

        // Create proposal via no-op UserOp
        bytes memory sig = _createProposalSignature(callData, nonce);
        PackedUserOperation memory noopOp = _createNoopUserOp(WALLET, sig);
        vm.prank(WALLET);
        timelockPolicy.checkUserOpPolicy(POLICY_ID, noopOp);

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

        // Create proposal via no-op UserOp
        bytes memory sig = _createProposalSignature(callData, nonce);
        PackedUserOperation memory noopOp = _createNoopUserOp(WALLET, sig);
        vm.prank(WALLET);
        timelockPolicy.checkUserOpPolicy(POLICY_ID, noopOp);

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
        // it should revert (TOB-KERNEL-20: signature validation not supported)
        vm.prank(WALLET);
        vm.expectRevert(TimelockPolicy.SignatureValidationNotSupported.selector);
        timelockPolicy.checkSignaturePolicy(POLICY_ID, address(0), bytes32(0), "");
    }

    function test_GivenNotInitialized_WhenCallingCheckSignaturePolicy() external whenCallingCheckSignaturePolicy {
        // it should revert (TOB-KERNEL-20: signature validation not supported)
        address uninitWallet = address(0xcccc);
        vm.prank(uninitWallet);
        vm.expectRevert(TimelockPolicy.SignatureValidationNotSupported.selector);
        timelockPolicy.checkSignaturePolicy(POLICY_ID, address(0), bytes32(0), "");
    }

    // ============ validateSignatureWithData Tests ============

    modifier whenCallingValidateSignatureWithData() {
        _;
    }

    function test_GivenDelayAndExpirationAreNonzero() external whenCallingValidateSignatureWithData {
        // it should revert (TOB-KERNEL-20: stateless signature validation not supported)
        bytes memory data = abi.encode(uint48(1 hours), uint48(1 days));
        vm.expectRevert(TimelockPolicy.StatelessValidationNotSupported.selector);
        timelockPolicy.validateSignatureWithData(bytes32(0), "", data);
    }

    function test_GivenDelayIsZero_WhenCallingValidateSignatureWithData()
        external
        whenCallingValidateSignatureWithData
    {
        // it should revert (TOB-KERNEL-20: stateless signature validation not supported)
        bytes memory data = abi.encode(uint48(0), uint48(1 days));
        vm.expectRevert(TimelockPolicy.StatelessValidationNotSupported.selector);
        timelockPolicy.validateSignatureWithData(bytes32(0), "", data);
    }

    function test_GivenExpirationIsZero_WhenCallingValidateSignatureWithData()
        external
        whenCallingValidateSignatureWithData
    {
        // it should revert (TOB-KERNEL-20: stateless signature validation not supported)
        bytes memory data = abi.encode(uint48(1 hours), uint48(0));
        vm.expectRevert(TimelockPolicy.StatelessValidationNotSupported.selector);
        timelockPolicy.validateSignatureWithData(bytes32(0), "", data);
    }

    // ============ validateSignatureWithDataWithSender Tests ============

    modifier whenCallingValidateSignatureWithDataWithSender() {
        _;
    }

    function test_GivenDelayAndExpirationAreNonzero_WhenCallingValidateSignatureWithDataWithSender()
        external
        whenCallingValidateSignatureWithDataWithSender
    {
        // it should revert (TOB-KERNEL-20: stateless signature validation not supported)
        bytes memory data = abi.encode(uint48(1 hours), uint48(1 days));
        vm.expectRevert(TimelockPolicy.StatelessValidationNotSupported.selector);
        timelockPolicy.validateSignatureWithDataWithSender(address(0), bytes32(0), "", data);
    }

    function test_GivenDelayIsZero_WhenCallingValidateSignatureWithDataWithSender()
        external
        whenCallingValidateSignatureWithDataWithSender
    {
        // it should revert (TOB-KERNEL-20: stateless signature validation not supported)
        bytes memory data = abi.encode(uint48(0), uint48(1 days));
        vm.expectRevert(TimelockPolicy.StatelessValidationNotSupported.selector);
        timelockPolicy.validateSignatureWithDataWithSender(address(0), bytes32(0), "", data);
    }

    function test_GivenExpirationIsZero_WhenCallingValidateSignatureWithDataWithSender()
        external
        whenCallingValidateSignatureWithDataWithSender
    {
        // it should revert (TOB-KERNEL-20: stateless signature validation not supported)
        bytes memory data = abi.encode(uint48(1 hours), uint48(0));
        vm.expectRevert(TimelockPolicy.StatelessValidationNotSupported.selector);
        timelockPolicy.validateSignatureWithDataWithSender(address(0), bytes32(0), "", data);
    }

    // ============ getProposal Tests ============

    modifier whenCallingGetProposal() {
        _;
    }

    function test_GivenProposalExists() external whenCallingGetProposal {
        // it should return status validAfter and validUntil
        bytes memory callData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "test");
        uint256 nonce = 1200;

        // Create proposal via no-op UserOp (creates Pending with timing)
        bytes memory sig = _createProposalSignature(callData, nonce);
        PackedUserOperation memory noopOp = _createNoopUserOp(WALLET, sig);
        vm.prank(WALLET);
        timelockPolicy.checkUserOpPolicy(POLICY_ID, noopOp);

        (TimelockPolicy.ProposalStatus status, uint256 validAfter, uint256 validUntil) =
            timelockPolicy.getProposal(WALLET, callData, nonce, POLICY_ID, WALLET);

        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Pending), "Status should be Pending");
        assertEq(validAfter, block.timestamp + DELAY, "validAfter should be correct");
        assertEq(validUntil, block.timestamp + DELAY + EXPIRATION, "validUntil should be correct");
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

    // Case 1: Empty calldata
    function test_GivenCalldataIsEmpty() external whenDetectingNoopCalldata {
        // it should be detected as noop
        bytes memory sig = _createProposalSignature("test", 0);
        PackedUserOperation memory userOp = _createNoopUserOp(WALLET, sig);

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        // If it's a no-op, it goes to creation path and returns 0
        assertEq(result, 0, "Empty calldata should be detected as noop");
    }

    // Case 2: ERC-7579 execute(CALLTYPE_SINGLE, abi.encodePacked(target, uint256(0))) — minimal decodeSingle()-compatible no-op
    function test_GivenCalldataIsERC7579ExecuteNoop() external whenDetectingNoopCalldata {
        // it should be detected as noop
        bytes32 mode =
            LibERC7579.encodeMode(LibERC7579.CALLTYPE_SINGLE, LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes22(0));
        bytes memory noopExecute =
            abi.encodeWithSelector(IERC7579Execution.execute.selector, mode, abi.encodePacked(address(0), uint256(0)));
        bytes memory sig = _createProposalSignature("test", 1);
        PackedUserOperation memory userOp = _createUserOpWithCalldata(WALLET, noopExecute, 0, sig);

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        assertEq(result, 0, "ERC-7579 execute noop should be detected as noop");
    }

    // Case 3: executeUserOp + empty inner calldata (just the 4-byte selector)
    function test_GivenCalldataIsExecuteUserOpEmpty() external whenDetectingNoopCalldata {
        // it should be detected as noop
        bytes memory executeUserOpNoop = abi.encodePacked(IAccountExecute.executeUserOp.selector);
        bytes memory sig = _createProposalSignature("test", 2);
        PackedUserOperation memory userOp = _createUserOpWithCalldata(WALLET, executeUserOpNoop, 0, sig);

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        assertEq(result, 0, "executeUserOp + empty should be detected as noop");
    }

    // Case 4: executeUserOp + ERC-7579 execute no-op
    function test_GivenCalldataIsExecuteUserOpWithERC7579Noop() external whenDetectingNoopCalldata {
        // it should be detected as noop
        bytes32 mode =
            LibERC7579.encodeMode(LibERC7579.CALLTYPE_SINGLE, LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes22(0));
        bytes memory noopExecute =
            abi.encodeWithSelector(IERC7579Execution.execute.selector, mode, abi.encodePacked(address(0), uint256(0)));
        bytes memory executeUserOpWrapped = abi.encodePacked(IAccountExecute.executeUserOp.selector, noopExecute);
        bytes memory sig = _createProposalSignature("test", 3);
        PackedUserOperation memory userOp = _createUserOpWithCalldata(WALLET, executeUserOpWrapped, 0, sig);

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        assertEq(result, 0, "executeUserOp + ERC-7579 execute noop should be detected as noop");
    }

    // Negative: non-empty arbitrary calldata
    function test_GivenCalldataIsNonEmpty() external whenDetectingNoopCalldata {
        // it should not be detected as noop
        bytes memory nonEmptyCalldata = hex"aabb";
        PackedUserOperation memory userOp = _createUserOpWithCalldata(WALLET, nonEmptyCalldata, 0, "");

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        // Not a no-op, goes to execution path, no proposal exists
        assertEq(result, SIG_VALIDATION_FAILED, "Non-empty calldata should not be noop");
    }

    // Negative: ERC-7579 execute with delegatecall mode
    function test_GivenCalldataIsERC7579ExecuteDelegatecall() external whenDetectingNoopCalldata {
        // it should not be detected as noop — CALLTYPE_DELEGATECALL
        bytes32 delegatecallMode =
            LibERC7579.encodeMode(LibERC7579.CALLTYPE_DELEGATECALL, LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes22(0));
        bytes memory delegatecallExecute = abi.encodeWithSelector(
            IERC7579Execution.execute.selector, delegatecallMode, abi.encodePacked(address(0), uint256(0))
        );
        PackedUserOperation memory userOp = _createUserOpWithCalldata(WALLET, delegatecallExecute, 0, "");

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        assertEq(result, SIG_VALIDATION_FAILED, "Delegatecall mode should not be noop");
    }

    // Negative: ERC-7579 execute with batch mode
    function test_GivenCalldataIsERC7579ExecuteBatch() external whenDetectingNoopCalldata {
        // it should not be detected as noop — CALLTYPE_BATCH
        bytes32 batchMode =
            LibERC7579.encodeMode(LibERC7579.CALLTYPE_BATCH, LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes22(0));
        bytes memory batchExecute = abi.encodeWithSelector(
            IERC7579Execution.execute.selector, batchMode, abi.encodePacked(address(0), uint256(0))
        );
        PackedUserOperation memory userOp = _createUserOpWithCalldata(WALLET, batchExecute, 0, "");

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        assertEq(result, SIG_VALIDATION_FAILED, "Batch mode should not be noop");
    }

    // Negative: ERC-7579 execute with non-empty execution data
    function test_GivenCalldataIsERC7579ExecuteWithData() external whenDetectingNoopCalldata {
        // it should not be detected as noop — has execution data
        bytes memory executeWithData =
            abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "some_execution_data");
        PackedUserOperation memory userOp = _createUserOpWithCalldata(WALLET, executeWithData, 0, "");

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        assertEq(result, SIG_VALIDATION_FAILED, "Execute with data should not be noop");
    }

    // Negative: executeUserOp wrapping a delegatecall ERC-7579 execute
    function test_GivenCalldataIsExecuteUserOpWithDelegatecall() external whenDetectingNoopCalldata {
        // it should not be detected as noop
        bytes32 delegatecallMode =
            LibERC7579.encodeMode(LibERC7579.CALLTYPE_DELEGATECALL, LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes22(0));
        bytes memory delegatecallExecute = abi.encodeWithSelector(
            IERC7579Execution.execute.selector, delegatecallMode, abi.encodePacked(address(0), uint256(0))
        );
        bytes memory wrapped = abi.encodePacked(IAccountExecute.executeUserOp.selector, delegatecallExecute);
        PackedUserOperation memory userOp = _createUserOpWithCalldata(WALLET, wrapped, 0, "");

        vm.prank(WALLET);
        uint256 result = timelockPolicy.checkUserOpPolicy(POLICY_ID, userOp);

        assertEq(result, SIG_VALIDATION_FAILED, "executeUserOp + delegatecall should not be noop");
    }

    // ============ _packValidationData Tests ============

    function test_WhenPackingValidationData() external {
        // it should correctly pack validAfter and validUntil
        // Test the packing by creating a proposal and checking the returned validation data
        bytes memory callData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "test");
        uint256 nonce = 1400;

        // Create proposal via no-op UserOp
        bytes memory sig = _createProposalSignature(callData, nonce);
        PackedUserOperation memory noopOp = _createNoopUserOp(WALLET, sig);
        vm.prank(WALLET);
        timelockPolicy.checkUserOpPolicy(POLICY_ID, noopOp);

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

    function test_GivenAttackerTriesToReexecuteAUsedProposal() external whenTestingSecurityScenarios {
        // it should return SIG_VALIDATION_FAILED
        bytes memory callData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "action");
        uint256 nonce = 1600;

        // Create proposal via no-op UserOp
        bytes memory sig = _createProposalSignature(callData, nonce);
        PackedUserOperation memory noopOp = _createNoopUserOp(WALLET, sig);
        vm.prank(WALLET);
        timelockPolicy.checkUserOpPolicy(POLICY_ID, noopOp);

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

        // Create proposal via no-op UserOp from WALLET
        bytes memory sig = _createProposalSignature(callData, nonce);
        PackedUserOperation memory noopOp = _createNoopUserOp(WALLET, sig);
        vm.prank(WALLET);
        timelockPolicy.checkUserOpPolicy(POLICY_ID, noopOp);

        vm.prank(ATTACKER);
        vm.expectRevert(TimelockPolicy.OnlyAccount.selector);
        timelockPolicy.cancelProposal(POLICY_ID, WALLET, callData, nonce);

        // Verify proposal is still pending
        (TimelockPolicy.ProposalStatus status,,) =
            timelockPolicy.getProposal(WALLET, callData, nonce, POLICY_ID, WALLET);
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Pending), "Proposal should still be Pending");
    }

    // ============ Guardian Cancellation Tests ============

    modifier whenTestingGuardianCancellation() {
        _;
    }

    function test_GivenGuardianIsSet_GuardianCanCancel() external whenTestingGuardianCancellation {
        // Setup: install policy with a guardian for a new wallet
        address guardianWallet = address(0xA001);
        address guardian = address(0xBEEF01);
        bytes32 guardianPolicyId = bytes32(uint256(2));

        bytes memory installData = abi.encode(guardianPolicyId, DELAY, EXPIRATION, guardian);
        vm.prank(guardianWallet);
        timelockPolicy.onInstall(installData);

        // Create proposal
        bytes memory callData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "guardian_test");
        uint256 nonce = 2000;
        bytes memory sig = _createProposalSignature(callData, nonce);
        PackedUserOperation memory noopOp = _createNoopUserOp(guardianWallet, sig);
        vm.prank(guardianWallet);
        timelockPolicy.checkUserOpPolicy(guardianPolicyId, noopOp);

        // Guardian cancels
        bytes32 expectedKey = keccak256(abi.encode(guardianWallet, keccak256(callData), nonce));
        vm.expectEmit(true, true, true, true);
        emit TimelockPolicy.ProposalCancelled(guardianWallet, guardianPolicyId, expectedKey);

        vm.prank(guardian);
        timelockPolicy.cancelProposal(guardianPolicyId, guardianWallet, callData, nonce);

        (TimelockPolicy.ProposalStatus status,,) =
            timelockPolicy.getProposal(guardianWallet, callData, nonce, guardianPolicyId, guardianWallet);
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Cancelled), "Guardian should be able to cancel");
    }

    function test_GivenGuardianIsSet_AccountCanStillCancel() external whenTestingGuardianCancellation {
        // Setup: install policy with a guardian for a new wallet
        address guardianWallet = address(0xA002);
        address guardian = address(0xBEEF02);
        bytes32 guardianPolicyId = bytes32(uint256(3));

        bytes memory installData = abi.encode(guardianPolicyId, DELAY, EXPIRATION, guardian);
        vm.prank(guardianWallet);
        timelockPolicy.onInstall(installData);

        // Create proposal
        bytes memory callData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "account_cancel");
        uint256 nonce = 2100;
        bytes memory sig = _createProposalSignature(callData, nonce);
        PackedUserOperation memory noopOp = _createNoopUserOp(guardianWallet, sig);
        vm.prank(guardianWallet);
        timelockPolicy.checkUserOpPolicy(guardianPolicyId, noopOp);

        // Account cancels (not guardian)
        vm.prank(guardianWallet);
        timelockPolicy.cancelProposal(guardianPolicyId, guardianWallet, callData, nonce);

        (TimelockPolicy.ProposalStatus status,,) =
            timelockPolicy.getProposal(guardianWallet, callData, nonce, guardianPolicyId, guardianWallet);
        assertEq(
            uint256(status), uint256(TimelockPolicy.ProposalStatus.Cancelled), "Account should still be able to cancel"
        );
    }

    function test_GivenGuardianIsSet_NonGuardianNonAccountCannotCancel() external whenTestingGuardianCancellation {
        // Setup: install policy with a guardian for a new wallet
        address guardianWallet = address(0xA003);
        address guardian = address(0xBEEF03);
        bytes32 guardianPolicyId = bytes32(uint256(4));

        bytes memory installData = abi.encode(guardianPolicyId, DELAY, EXPIRATION, guardian);
        vm.prank(guardianWallet);
        timelockPolicy.onInstall(installData);

        // Create proposal
        bytes memory callData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "attacker_test");
        uint256 nonce = 2200;
        bytes memory sig = _createProposalSignature(callData, nonce);
        PackedUserOperation memory noopOp = _createNoopUserOp(guardianWallet, sig);
        vm.prank(guardianWallet);
        timelockPolicy.checkUserOpPolicy(guardianPolicyId, noopOp);

        // Attacker tries to cancel — should revert
        vm.prank(ATTACKER);
        vm.expectRevert(TimelockPolicy.OnlyAccount.selector);
        timelockPolicy.cancelProposal(guardianPolicyId, guardianWallet, callData, nonce);
    }

    function test_GivenNoGuardian_OnlyAccountCanCancel() external whenTestingGuardianCancellation {
        // WALLET has guardian = address(0) from setUp
        // Create proposal
        bytes memory callData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "no_guardian");
        uint256 nonce = 2300;
        bytes memory sig = _createProposalSignature(callData, nonce);
        PackedUserOperation memory noopOp = _createNoopUserOp(WALLET, sig);
        vm.prank(WALLET);
        timelockPolicy.checkUserOpPolicy(POLICY_ID, noopOp);

        // Non-account tries to cancel — should revert (no guardian set, so only account can cancel)
        vm.prank(ATTACKER);
        vm.expectRevert(TimelockPolicy.OnlyAccount.selector);
        timelockPolicy.cancelProposal(POLICY_ID, WALLET, callData, nonce);

        // Account itself can cancel
        vm.prank(WALLET);
        timelockPolicy.cancelProposal(POLICY_ID, WALLET, callData, nonce);

        (TimelockPolicy.ProposalStatus status,,) =
            timelockPolicy.getProposal(WALLET, callData, nonce, POLICY_ID, WALLET);
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Cancelled), "Account should be able to cancel");
    }

    function test_GivenGuardianIsSet_ConfigStoresGuardian() external whenTestingGuardianCancellation {
        address guardianWallet = address(0xA004);
        address guardian = address(0xBEEF04);
        bytes32 guardianPolicyId = bytes32(uint256(5));

        bytes memory installData = abi.encode(guardianPolicyId, DELAY, EXPIRATION, guardian);
        vm.prank(guardianWallet);
        timelockPolicy.onInstall(installData);

        (,, address storedGuardian, bool initialized) = timelockPolicy.timelockConfig(guardianPolicyId, guardianWallet);
        assertEq(storedGuardian, guardian, "Guardian should be stored in config");
        assertTrue(initialized, "Should be initialized");
    }

    // ============ Guardian Isolation and Advanced Tests ============

    function test_GivenGuardianForPolicyA_CannotCancelProposalInPolicyB() external whenTestingGuardianCancellation {
        // it should revert with OnlyAccount when guardian from policy A tries to cancel policy B proposal
        address wallet = address(0xA100);
        address guardianA = address(0xBEEF10);
        bytes32 policyIdA = bytes32(uint256(10));
        bytes32 policyIdB = bytes32(uint256(11));

        // Install policy A with guardianA
        bytes memory installDataA = abi.encode(policyIdA, DELAY, EXPIRATION, guardianA);
        vm.prank(wallet);
        timelockPolicy.onInstall(installDataA);

        // Install policy B with no guardian
        bytes memory installDataB = abi.encode(policyIdB, DELAY, EXPIRATION, address(0));
        vm.prank(wallet);
        timelockPolicy.onInstall(installDataB);

        // Create proposal under policy B
        bytes memory callData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "policy_b_test");
        uint256 nonce = 3000;
        bytes memory sig = _createProposalSignature(callData, nonce);
        PackedUserOperation memory noopOp = _createNoopUserOp(wallet, sig);
        vm.prank(wallet);
        timelockPolicy.checkUserOpPolicy(policyIdB, noopOp);

        // Guardian A tries to cancel proposal in policy B — should fail
        vm.prank(guardianA);
        vm.expectRevert(TimelockPolicy.OnlyAccount.selector);
        timelockPolicy.cancelProposal(policyIdB, wallet, callData, nonce);

        // Verify proposal is still pending
        (TimelockPolicy.ProposalStatus status,,) =
            timelockPolicy.getProposal(wallet, callData, nonce, policyIdB, wallet);
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Pending), "Proposal should still be pending");
    }

    function test_GivenGuardianForWalletA_CannotCancelProposalForWalletB() external whenTestingGuardianCancellation {
        // it should revert with OnlyAccount when guardian for wallet A tries to cancel wallet B proposal
        address walletA = address(0xA200);
        address walletB = address(0xA201);
        address guardianA = address(0xBEEF20);
        bytes32 sharedPolicyId = bytes32(uint256(20));

        // Install policy for wallet A with guardianA
        bytes memory installDataA = abi.encode(sharedPolicyId, DELAY, EXPIRATION, guardianA);
        vm.prank(walletA);
        timelockPolicy.onInstall(installDataA);

        // Install policy for wallet B with no guardian
        bytes memory installDataB = abi.encode(sharedPolicyId, DELAY, EXPIRATION, address(0));
        vm.prank(walletB);
        timelockPolicy.onInstall(installDataB);

        // Create proposal for wallet B
        bytes memory callData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "wallet_b_test");
        uint256 nonce = 3100;
        bytes memory sig = _createProposalSignature(callData, nonce);
        PackedUserOperation memory noopOp = _createNoopUserOp(walletB, sig);
        vm.prank(walletB);
        timelockPolicy.checkUserOpPolicy(sharedPolicyId, noopOp);

        // Guardian A tries to cancel wallet B's proposal — should fail
        vm.prank(guardianA);
        vm.expectRevert(TimelockPolicy.OnlyAccount.selector);
        timelockPolicy.cancelProposal(sharedPolicyId, walletB, callData, nonce);

        // Verify wallet B's proposal is still pending
        (TimelockPolicy.ProposalStatus status,,) =
            timelockPolicy.getProposal(walletB, callData, nonce, sharedPolicyId, walletB);
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Pending), "Proposal should still be pending");
    }

    function test_GivenProposalIsExecuted_GuardianCannotCancel() external whenTestingGuardianCancellation {
        // it should revert with ProposalNotPending after proposal is executed
        address guardianWallet = address(0xA300);
        address guardian = address(0xBEEF30);
        bytes32 guardianPolicyId = bytes32(uint256(30));

        bytes memory installData = abi.encode(guardianPolicyId, DELAY, EXPIRATION, guardian);
        vm.prank(guardianWallet);
        timelockPolicy.onInstall(installData);

        // Create and execute proposal
        bytes memory callData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "execute_test");
        uint256 nonce = 3200;
        bytes memory sig = _createProposalSignature(callData, nonce);
        PackedUserOperation memory noopOp = _createNoopUserOp(guardianWallet, sig);
        vm.prank(guardianWallet);
        timelockPolicy.checkUserOpPolicy(guardianPolicyId, noopOp);

        // Warp past delay and execute
        vm.warp(block.timestamp + DELAY + 1);
        PackedUserOperation memory executeOp = _createUserOpWithCalldata(guardianWallet, callData, nonce, "");
        vm.prank(guardianWallet);
        timelockPolicy.checkUserOpPolicy(guardianPolicyId, executeOp);

        // Guardian tries to cancel executed proposal — should fail
        vm.prank(guardian);
        vm.expectRevert(TimelockPolicy.ProposalNotPending.selector);
        timelockPolicy.cancelProposal(guardianPolicyId, guardianWallet, callData, nonce);
    }

    function test_GivenProposalIsCancelled_GuardianCannotCancelAgain() external whenTestingGuardianCancellation {
        // it should revert with ProposalNotPending on double cancel
        address guardianWallet = address(0xA400);
        address guardian = address(0xBEEF40);
        bytes32 guardianPolicyId = bytes32(uint256(40));

        bytes memory installData = abi.encode(guardianPolicyId, DELAY, EXPIRATION, guardian);
        vm.prank(guardianWallet);
        timelockPolicy.onInstall(installData);

        // Create proposal
        bytes memory callData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "cancel_test");
        uint256 nonce = 3300;
        bytes memory sig = _createProposalSignature(callData, nonce);
        PackedUserOperation memory noopOp = _createNoopUserOp(guardianWallet, sig);
        vm.prank(guardianWallet);
        timelockPolicy.checkUserOpPolicy(guardianPolicyId, noopOp);

        // Guardian cancels
        vm.prank(guardian);
        timelockPolicy.cancelProposal(guardianPolicyId, guardianWallet, callData, nonce);

        // Guardian tries to cancel again — should fail
        vm.prank(guardian);
        vm.expectRevert(TimelockPolicy.ProposalNotPending.selector);
        timelockPolicy.cancelProposal(guardianPolicyId, guardianWallet, callData, nonce);
    }

    function test_GivenDelayPassed_GuardianCanStillCancel() external whenTestingGuardianCancellation {
        // it should allow guardian to cancel even when proposal is executable
        address guardianWallet = address(0xA500);
        address guardian = address(0xBEEF50);
        bytes32 guardianPolicyId = bytes32(uint256(50));

        bytes memory installData = abi.encode(guardianPolicyId, DELAY, EXPIRATION, guardian);
        vm.prank(guardianWallet);
        timelockPolicy.onInstall(installData);

        // Create proposal
        bytes memory callData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "after_delay");
        uint256 nonce = 3400;
        bytes memory sig = _createProposalSignature(callData, nonce);
        PackedUserOperation memory noopOp = _createNoopUserOp(guardianWallet, sig);
        vm.prank(guardianWallet);
        timelockPolicy.checkUserOpPolicy(guardianPolicyId, noopOp);

        // Warp past delay — proposal is now executable
        vm.warp(block.timestamp + DELAY + 1);

        // Guardian cancels even though proposal is executable
        vm.prank(guardian);
        timelockPolicy.cancelProposal(guardianPolicyId, guardianWallet, callData, nonce);

        (TimelockPolicy.ProposalStatus status,,) =
            timelockPolicy.getProposal(guardianWallet, callData, nonce, guardianPolicyId, guardianWallet);
        assertEq(
            uint256(status), uint256(TimelockPolicy.ProposalStatus.Cancelled), "Guardian should cancel even after delay"
        );

        // Verify execution now fails
        PackedUserOperation memory executeOp = _createUserOpWithCalldata(guardianWallet, callData, nonce, "");
        vm.prank(guardianWallet);
        uint256 result = timelockPolicy.checkUserOpPolicy(guardianPolicyId, executeOp);
        assertEq(result, SIG_VALIDATION_FAILED, "Execution should fail after guardian cancel");
    }

    function test_GivenReinstallWithNewGuardian_OldGuardianCannotCancel() external whenTestingGuardianCancellation {
        // it should prevent old guardian from canceling after reinstall with new guardian
        address guardianWallet = address(0xA600);
        address oldGuardian = address(0xBEEF60);
        address newGuardian = address(0xBEEF61);
        bytes32 guardianPolicyId = bytes32(uint256(60));

        // Install with old guardian
        bytes memory installData1 = abi.encode(guardianPolicyId, DELAY, EXPIRATION, oldGuardian);
        vm.prank(guardianWallet);
        timelockPolicy.onInstall(installData1);

        // Uninstall
        vm.prank(guardianWallet);
        timelockPolicy.onUninstall(abi.encode(guardianPolicyId));

        // Reinstall with new guardian
        bytes memory installData2 = abi.encode(guardianPolicyId, DELAY, EXPIRATION, newGuardian);
        vm.prank(guardianWallet);
        timelockPolicy.onInstall(installData2);

        // Create proposal under new installation
        bytes memory callData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "reinstall_test");
        uint256 nonce = 3500;
        bytes memory sig = _createProposalSignature(callData, nonce);
        PackedUserOperation memory noopOp = _createNoopUserOp(guardianWallet, sig);
        vm.prank(guardianWallet);
        timelockPolicy.checkUserOpPolicy(guardianPolicyId, noopOp);

        // Old guardian tries to cancel — should fail
        vm.prank(oldGuardian);
        vm.expectRevert(TimelockPolicy.OnlyAccount.selector);
        timelockPolicy.cancelProposal(guardianPolicyId, guardianWallet, callData, nonce);

        // New guardian can cancel
        vm.prank(newGuardian);
        timelockPolicy.cancelProposal(guardianPolicyId, guardianWallet, callData, nonce);

        (TimelockPolicy.ProposalStatus status,,) =
            timelockPolicy.getProposal(guardianWallet, callData, nonce, guardianPolicyId, guardianWallet);
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Cancelled), "New guardian should cancel");
    }

    function test_GivenGuardianCancels_NewProposalWithDifferentNonceWorks() external whenTestingGuardianCancellation {
        // it should allow re-proposal with different nonce after guardian cancel
        address guardianWallet = address(0xA700);
        address guardian = address(0xBEEF70);
        bytes32 guardianPolicyId = bytes32(uint256(70));

        bytes memory installData = abi.encode(guardianPolicyId, DELAY, EXPIRATION, guardian);
        vm.prank(guardianWallet);
        timelockPolicy.onInstall(installData);

        // Create and cancel first proposal
        bytes memory callData = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "reproposal");
        uint256 nonce1 = 3600;
        bytes memory sig1 = _createProposalSignature(callData, nonce1);
        PackedUserOperation memory noopOp1 = _createNoopUserOp(guardianWallet, sig1);
        vm.prank(guardianWallet);
        timelockPolicy.checkUserOpPolicy(guardianPolicyId, noopOp1);

        vm.prank(guardian);
        timelockPolicy.cancelProposal(guardianPolicyId, guardianWallet, callData, nonce1);

        // Create new proposal with different nonce, same calldata
        uint256 nonce2 = 3601;
        bytes memory sig2 = _createProposalSignature(callData, nonce2);
        PackedUserOperation memory noopOp2 = _createNoopUserOp(guardianWallet, sig2);
        vm.prank(guardianWallet);
        uint256 result = timelockPolicy.checkUserOpPolicy(guardianPolicyId, noopOp2);
        assertEq(result, 0, "New proposal creation should succeed");

        // Verify new proposal exists and old is cancelled
        (TimelockPolicy.ProposalStatus status1,,) =
            timelockPolicy.getProposal(guardianWallet, callData, nonce1, guardianPolicyId, guardianWallet);
        (TimelockPolicy.ProposalStatus status2,,) =
            timelockPolicy.getProposal(guardianWallet, callData, nonce2, guardianPolicyId, guardianWallet);
        assertEq(uint256(status1), uint256(TimelockPolicy.ProposalStatus.Cancelled), "Old proposal should be cancelled");
        assertEq(uint256(status2), uint256(TimelockPolicy.ProposalStatus.Pending), "New proposal should be pending");
    }
}
