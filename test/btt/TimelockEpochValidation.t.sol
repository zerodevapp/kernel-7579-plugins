// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {TimelockPolicy} from "src/policies/TimelockPolicy.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

/**
 * @title TimelockEpochValidationTest
 * @notice BTT tests for the epoch-based validation fix in TimelockPolicy
 * @dev Tests the fix for TOB-KERNEL-2: Stale proposals persisting across reinstalls
 */
contract TimelockEpochValidationTest is Test {
    TimelockPolicy public timelockPolicy;

    address constant WALLET = address(0x1234);
    address constant WALLET2 = address(0x5678);
    address constant ATTACKER = address(0xBAD);

    uint48 constant DELAY = 1 days;
    uint48 constant EXPIRATION_PERIOD = 1 days;

    bytes32 constant POLICY_ID_1 = keccak256("POLICY_ID_1");
    bytes32 constant POLICY_ID_2 = keccak256("POLICY_ID_2");

    uint256 constant SIG_VALIDATION_FAILED_UINT = 1;

    function setUp() public {
        timelockPolicy = new TimelockPolicy();
    }

    function _installData() internal pure returns (bytes memory) {
        return abi.encode(DELAY, EXPIRATION_PERIOD);
    }

    function _installPolicy(address wallet, bytes32 policyId) internal {
        vm.prank(wallet);
        timelockPolicy.onInstall(abi.encodePacked(policyId, _installData()));
    }

    function _uninstallPolicy(address wallet, bytes32 policyId) internal {
        vm.prank(wallet);
        timelockPolicy.onUninstall(abi.encodePacked(policyId, ""));
    }

    function _createProposal(address wallet, bytes32 policyId, bytes memory callData, uint256 nonce) internal {
        vm.prank(wallet);
        timelockPolicy.createProposal(policyId, wallet, callData, nonce);
    }

    function _createUserOp(address sender, bytes memory callData, uint256 nonce)
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
            signature: ""
        });
    }

    function _approveProposal(address wallet, bytes32 policyId, bytes memory callData, uint256 nonce) internal {
        bytes memory sig = abi.encodePacked(bytes32(callData.length), callData, bytes32(nonce), bytes1(0x00));
        PackedUserOperation memory noopOp = PackedUserOperation({
            sender: wallet,
            nonce: 0,
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(abi.encodePacked(uint128(100000), uint128(200000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: "",
            signature: sig
        });
        vm.prank(wallet);
        timelockPolicy.checkUserOpPolicy(policyId, noopOp);
    }

    // ==================== Installing the Policy ====================

    modifier whenInstallingThePolicy() {
        _;
    }

    function test_GivenItIsTheFirstInstallation() external whenInstallingThePolicy {
        // Check epoch before installation
        uint256 epochBefore = timelockPolicy.currentEpoch(POLICY_ID_1, WALLET);
        assertEq(epochBefore, 0, "Epoch should be 0 before first install");

        // Install the policy
        _installPolicy(WALLET, POLICY_ID_1);

        // it should set currentEpoch to 1
        uint256 epochAfter = timelockPolicy.currentEpoch(POLICY_ID_1, WALLET);
        assertEq(epochAfter, 1, "Epoch should be 1 after first install");

        // it should initialize the policy config
        (uint48 delay, uint48 expirationPeriod, bool initialized) =
            timelockPolicy.timelockConfig(POLICY_ID_1, WALLET);
        assertTrue(initialized, "Policy should be initialized");
        assertEq(delay, DELAY, "Delay should match");
        assertEq(expirationPeriod, EXPIRATION_PERIOD, "Expiration period should match");
    }

    function test_GivenThePolicyWasPreviouslyUninstalled() external whenInstallingThePolicy {
        // First installation
        _installPolicy(WALLET, POLICY_ID_1);
        uint256 epochAfterFirstInstall = timelockPolicy.currentEpoch(POLICY_ID_1, WALLET);
        assertEq(epochAfterFirstInstall, 1, "Epoch should be 1 after first install");

        // Uninstall
        _uninstallPolicy(WALLET, POLICY_ID_1);

        // Reinstall
        _installPolicy(WALLET, POLICY_ID_1);

        // it should increment the epoch counter
        // it should set currentEpoch to previous epoch plus 1
        uint256 epochAfterReinstall = timelockPolicy.currentEpoch(POLICY_ID_1, WALLET);
        assertEq(epochAfterReinstall, 2, "Epoch should be 2 after reinstall");
    }

    function test_GivenMultipleReinstallCyclesOccur() external whenInstallingThePolicy {
        // First installation
        _installPolicy(WALLET, POLICY_ID_1);
        assertEq(timelockPolicy.currentEpoch(POLICY_ID_1, WALLET), 1, "Epoch should be 1");

        // First reinstall cycle
        _uninstallPolicy(WALLET, POLICY_ID_1);
        _installPolicy(WALLET, POLICY_ID_1);

        // it should increment epoch on each install
        assertEq(timelockPolicy.currentEpoch(POLICY_ID_1, WALLET), 2, "Epoch should be 2");

        // Second reinstall cycle
        _uninstallPolicy(WALLET, POLICY_ID_1);
        _installPolicy(WALLET, POLICY_ID_1);
        assertEq(timelockPolicy.currentEpoch(POLICY_ID_1, WALLET), 3, "Epoch should be 3");

        // Third reinstall cycle
        _uninstallPolicy(WALLET, POLICY_ID_1);
        _installPolicy(WALLET, POLICY_ID_1);

        // it should track epoch correctly after 3 reinstalls
        assertEq(timelockPolicy.currentEpoch(POLICY_ID_1, WALLET), 4, "Epoch should be 4 after 3 reinstalls");
    }

    // ==================== Creating a Proposal ====================

    modifier whenCreatingAProposal() {
        _;
    }

    function test_GivenThePolicyIsInstalled() external whenCreatingAProposal {
        _installPolicy(WALLET, POLICY_ID_1);

        bytes memory callData = hex"1234";
        uint256 nonce = 1;

        _createProposal(WALLET, POLICY_ID_1, callData, nonce);

        // it should store the current epoch in the proposal
        // it should be in Proposed (inert) status with no timing
        bytes32 userOpKey = timelockPolicy.computeUserOpKey(WALLET, callData, nonce);
        (
            TimelockPolicy.ProposalStatus status,
            uint48 validAfter,
            uint48 validUntil,
            uint256 proposalEpoch
        ) = timelockPolicy.proposals(userOpKey, POLICY_ID_1, WALLET);

        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Proposed), "Proposal should be Proposed (inert)");
        assertEq(proposalEpoch, 1, "Proposal epoch should match current epoch (1)");
        assertEq(validAfter, 0, "validAfter should be 0 (inert)");
        assertEq(validUntil, 0, "validUntil should be 0 (inert)");
    }

    function test_GivenCreatingViaCreateProposalFunction() external whenCreatingAProposal {
        _installPolicy(WALLET, POLICY_ID_1);

        bytes memory callData = hex"5678";
        uint256 nonce = 42;

        uint256 epoch = timelockPolicy.currentEpoch(POLICY_ID_1, WALLET);

        _createProposal(WALLET, POLICY_ID_1, callData, nonce);

        // it should record the epoch at creation time (proposal is inert)
        bytes32 userOpKey = timelockPolicy.computeUserOpKey(WALLET, callData, nonce);
        (TimelockPolicy.ProposalStatus status,,, uint256 proposalEpoch) = timelockPolicy.proposals(userOpKey, POLICY_ID_1, WALLET);

        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Proposed), "Should be Proposed");
        assertEq(proposalEpoch, epoch, "Proposal epoch should equal current epoch at creation");
    }

    // ==================== Executing a Proposal ====================

    modifier whenExecutingAProposal() {
        _;
    }

    modifier givenTheProposalWasCreatedInTheCurrentEpoch() {
        _;
    }

    function test_GivenTheTimelockHasPassed()
        external
        whenExecutingAProposal
        givenTheProposalWasCreatedInTheCurrentEpoch
    {
        _installPolicy(WALLET, POLICY_ID_1);

        bytes memory callData = hex"1234";
        uint256 nonce = 1;

        _createProposal(WALLET, POLICY_ID_1, callData, nonce);

        // Approve the proposal (starts the clock)
        _approveProposal(WALLET, POLICY_ID_1, callData, nonce);

        // Warp past the timelock delay
        vm.warp(block.timestamp + DELAY + 1);

        PackedUserOperation memory userOp = _createUserOp(WALLET, callData, nonce);

        vm.prank(WALLET);
        uint256 validationResult = timelockPolicy.checkUserOpPolicy(POLICY_ID_1, userOp);

        // it should return success validation data (not SIG_VALIDATION_FAILED_UINT)
        assertTrue(validationResult != SIG_VALIDATION_FAILED_UINT, "Validation should succeed");

        // it should mark proposal as executed
        bytes32 userOpKey = timelockPolicy.computeUserOpKey(WALLET, callData, nonce);
        (TimelockPolicy.ProposalStatus status,,,) = timelockPolicy.proposals(userOpKey, POLICY_ID_1, WALLET);
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Executed), "Proposal should be executed");
    }

    function test_GivenTheProposalWasCreatedBeforeUninstallAndReinstall() external whenExecutingAProposal {
        _installPolicy(WALLET, POLICY_ID_1);

        bytes memory callData = hex"1234";
        uint256 nonce = 1;

        // Create proposal in epoch 1 (inert)
        _createProposal(WALLET, POLICY_ID_1, callData, nonce);

        // Approve the proposal (starts the clock, epoch 1)
        _approveProposal(WALLET, POLICY_ID_1, callData, nonce);

        // Warp past the timelock delay
        vm.warp(block.timestamp + DELAY + 1);

        // Uninstall and reinstall (epoch becomes 2)
        _uninstallPolicy(WALLET, POLICY_ID_1);
        _installPolicy(WALLET, POLICY_ID_1);

        // Try to execute the stale proposal
        PackedUserOperation memory userOp = _createUserOp(WALLET, callData, nonce);

        vm.prank(WALLET);
        uint256 validationResult = timelockPolicy.checkUserOpPolicy(POLICY_ID_1, userOp);

        // it should return SIG_VALIDATION_FAILED
        assertEq(validationResult, SIG_VALIDATION_FAILED_UINT, "Stale proposal should fail validation");

        // it should not mark proposal as executed (still Pending from epoch 1)
        bytes32 userOpKey = timelockPolicy.computeUserOpKey(WALLET, callData, nonce);
        (TimelockPolicy.ProposalStatus status,,,) = timelockPolicy.proposals(userOpKey, POLICY_ID_1, WALLET);
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Pending), "Proposal should still be Pending");
    }

    function test_GivenTheProposalEpochDoesNotMatchCurrentEpoch() external whenExecutingAProposal {
        _installPolicy(WALLET, POLICY_ID_1);

        bytes memory callData = hex"abcd";
        uint256 nonce = 5;

        // Create and approve proposal in epoch 1
        _createProposal(WALLET, POLICY_ID_1, callData, nonce);
        _approveProposal(WALLET, POLICY_ID_1, callData, nonce);

        bytes32 userOpKey = timelockPolicy.computeUserOpKey(WALLET, callData, nonce);
        (,,, uint256 proposalEpoch) = timelockPolicy.proposals(userOpKey, POLICY_ID_1, WALLET);
        assertEq(proposalEpoch, 1, "Proposal should be in epoch 1");

        // Warp and do multiple reinstalls to get to epoch 3
        vm.warp(block.timestamp + DELAY + 1);
        _uninstallPolicy(WALLET, POLICY_ID_1);
        _installPolicy(WALLET, POLICY_ID_1);
        _uninstallPolicy(WALLET, POLICY_ID_1);
        _installPolicy(WALLET, POLICY_ID_1);

        assertEq(timelockPolicy.currentEpoch(POLICY_ID_1, WALLET), 3, "Current epoch should be 3");

        // Try to execute
        PackedUserOperation memory userOp = _createUserOp(WALLET, callData, nonce);

        vm.prank(WALLET);
        uint256 validationResult = timelockPolicy.checkUserOpPolicy(POLICY_ID_1, userOp);

        // it should reject the stale proposal
        assertEq(validationResult, SIG_VALIDATION_FAILED_UINT, "Should reject stale proposal");

        // it should leave proposal status unchanged
        (TimelockPolicy.ProposalStatus statusAfter,,,) = timelockPolicy.proposals(userOpKey, POLICY_ID_1, WALLET);
        assertEq(
            uint256(statusAfter),
            uint256(TimelockPolicy.ProposalStatus.Pending),
            "Proposal status should remain Pending"
        );
    }

    // ==================== Uninstalling and Reinstalling ====================

    modifier whenUninstallingAndReinstallingThePolicy() {
        _;
    }

    modifier givenAProposalExistsBeforeUninstall() {
        _;
    }

    function test_WhenThePolicyIsUninstalled()
        external
        whenUninstallingAndReinstallingThePolicy
        givenAProposalExistsBeforeUninstall
    {
        _installPolicy(WALLET, POLICY_ID_1);

        bytes memory callData = hex"1234";
        uint256 nonce = 1;

        _createProposal(WALLET, POLICY_ID_1, callData, nonce);

        uint256 epochBeforeUninstall = timelockPolicy.currentEpoch(POLICY_ID_1, WALLET);

        // Uninstall
        _uninstallPolicy(WALLET, POLICY_ID_1);

        // it should delete the policy config
        (,, bool initialized) = timelockPolicy.timelockConfig(POLICY_ID_1, WALLET);
        assertFalse(initialized, "Policy config should be deleted");

        // it should preserve the epoch counter
        uint256 epochAfterUninstall = timelockPolicy.currentEpoch(POLICY_ID_1, WALLET);
        assertEq(epochAfterUninstall, epochBeforeUninstall, "Epoch should be preserved after uninstall");
    }

    function test_WhenThePolicyIsReinstalled()
        external
        whenUninstallingAndReinstallingThePolicy
        givenAProposalExistsBeforeUninstall
    {
        _installPolicy(WALLET, POLICY_ID_1);

        bytes memory callData = hex"1234";
        uint256 nonce = 1;

        // Create and approve in epoch 1
        _createProposal(WALLET, POLICY_ID_1, callData, nonce);
        _approveProposal(WALLET, POLICY_ID_1, callData, nonce);

        uint256 epochBeforeUninstall = timelockPolicy.currentEpoch(POLICY_ID_1, WALLET);

        _uninstallPolicy(WALLET, POLICY_ID_1);

        // Reinstall
        _installPolicy(WALLET, POLICY_ID_1);

        // it should increment the epoch
        uint256 epochAfterReinstall = timelockPolicy.currentEpoch(POLICY_ID_1, WALLET);
        assertEq(epochAfterReinstall, epochBeforeUninstall + 1, "Epoch should increment on reinstall");

        // it should invalidate old proposals implicitly
        vm.warp(block.timestamp + DELAY + 1);
        PackedUserOperation memory userOp = _createUserOp(WALLET, callData, nonce);

        vm.prank(WALLET);
        uint256 validationResult = timelockPolicy.checkUserOpPolicy(POLICY_ID_1, userOp);
        assertEq(validationResult, SIG_VALIDATION_FAILED_UINT, "Old proposal should be invalid");

        // it should allow new proposals with new epoch (Proposed status)
        bytes memory newCallData = hex"5678";
        uint256 newNonce = 2;

        _createProposal(WALLET, POLICY_ID_1, newCallData, newNonce);

        bytes32 newUserOpKey = timelockPolicy.computeUserOpKey(WALLET, newCallData, newNonce);
        (TimelockPolicy.ProposalStatus status,,, uint256 newProposalEpoch) =
            timelockPolicy.proposals(newUserOpKey, POLICY_ID_1, WALLET);

        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Proposed), "New proposal should be Proposed");
        assertEq(newProposalEpoch, epochAfterReinstall, "New proposal should have current epoch");
    }

    // ==================== Epoch Storage Per Policy ID ====================

    modifier whenEpochIsStoredPerPolicyID() {
        _;
    }

    function test_GivenTwoDifferentPolicyIDsForSameWallet() external whenEpochIsStoredPerPolicyID {
        // Install policy 1
        _installPolicy(WALLET, POLICY_ID_1);
        assertEq(timelockPolicy.currentEpoch(POLICY_ID_1, WALLET), 1, "Policy 1 should be epoch 1");

        // Install policy 2
        _installPolicy(WALLET, POLICY_ID_2);
        assertEq(timelockPolicy.currentEpoch(POLICY_ID_2, WALLET), 1, "Policy 2 should be epoch 1");

        // Reinstall policy 1 twice
        _uninstallPolicy(WALLET, POLICY_ID_1);
        _installPolicy(WALLET, POLICY_ID_1);
        _uninstallPolicy(WALLET, POLICY_ID_1);
        _installPolicy(WALLET, POLICY_ID_1);

        // it should track separate epochs for each policy ID
        assertEq(timelockPolicy.currentEpoch(POLICY_ID_1, WALLET), 3, "Policy 1 should be epoch 3");

        // it should not cross contaminate epochs
        assertEq(timelockPolicy.currentEpoch(POLICY_ID_2, WALLET), 1, "Policy 2 should still be epoch 1");
    }

    function test_GivenSamePolicyIDForDifferentWallets() external whenEpochIsStoredPerPolicyID {
        // Install for wallet 1
        _installPolicy(WALLET, POLICY_ID_1);
        assertEq(timelockPolicy.currentEpoch(POLICY_ID_1, WALLET), 1, "Wallet 1 should be epoch 1");

        // Install for wallet 2
        _installPolicy(WALLET2, POLICY_ID_1);
        assertEq(timelockPolicy.currentEpoch(POLICY_ID_1, WALLET2), 1, "Wallet 2 should be epoch 1");

        // Reinstall for wallet 1 multiple times
        _uninstallPolicy(WALLET, POLICY_ID_1);
        _installPolicy(WALLET, POLICY_ID_1);
        _uninstallPolicy(WALLET, POLICY_ID_1);
        _installPolicy(WALLET, POLICY_ID_1);

        // it should track separate epochs for each wallet
        assertEq(timelockPolicy.currentEpoch(POLICY_ID_1, WALLET), 3, "Wallet 1 should be epoch 3");

        // it should not affect other wallets epoch on reinstall
        assertEq(timelockPolicy.currentEpoch(POLICY_ID_1, WALLET2), 1, "Wallet 2 should still be epoch 1");
    }

    // ==================== Full Attack Scenario ====================

    modifier whenVerifyingFullAttackScenario() {
        _;
    }

    function test_WhenAttackerTriesToExecuteOldProposal() external whenVerifyingFullAttackScenario {
        // User installs policy
        _installPolicy(WALLET, POLICY_ID_1);
        assertEq(timelockPolicy.currentEpoch(POLICY_ID_1, WALLET), 1, "Should start at epoch 1");

        // Attacker creates malicious proposal
        bytes memory maliciousCallData = hex"deadbeef";
        uint256 maliciousNonce = 666;

        vm.prank(ATTACKER);
        timelockPolicy.createProposal(POLICY_ID_1, WALLET, maliciousCallData, maliciousNonce);

        // Time passes, timelock expires
        vm.warp(block.timestamp + DELAY + 1);

        // User decides to uninstall and reinstall
        _uninstallPolicy(WALLET, POLICY_ID_1);
        _installPolicy(WALLET, POLICY_ID_1);

        assertEq(timelockPolicy.currentEpoch(POLICY_ID_1, WALLET), 2, "Should be at epoch 2");

        // Attacker tries to execute the old proposal
        PackedUserOperation memory maliciousUserOp = _createUserOp(WALLET, maliciousCallData, maliciousNonce);

        vm.prank(WALLET);
        uint256 validationResult = timelockPolicy.checkUserOpPolicy(POLICY_ID_1, maliciousUserOp);

        // it should fail due to epoch mismatch
        assertEq(validationResult, SIG_VALIDATION_FAILED_UINT, "Attack should be thwarted by epoch check");
    }

    function test_WhenUserCreatesNewProposalAfterReinstall() external whenVerifyingFullAttackScenario {
        // User installs policy
        _installPolicy(WALLET, POLICY_ID_1);

        // User uninstalls and reinstalls
        _uninstallPolicy(WALLET, POLICY_ID_1);
        _installPolicy(WALLET, POLICY_ID_1);

        // User creates and approves legitimate proposal with new epoch
        bytes memory callData = hex"abcd";
        uint256 userNonce = 200;
        _createProposal(WALLET, POLICY_ID_1, callData, userNonce);
        _approveProposal(WALLET, POLICY_ID_1, callData, userNonce);

        vm.warp(block.timestamp + DELAY + 1);

        PackedUserOperation memory userOp = _createUserOp(WALLET, callData, userNonce);

        vm.prank(WALLET);
        uint256 validationResult = timelockPolicy.checkUserOpPolicy(POLICY_ID_1, userOp);

        // it should succeed with new epoch
        assertTrue(validationResult != SIG_VALIDATION_FAILED_UINT, "User's new proposal should succeed");
    }

    function test_WhenOneUserReinstallsDoesNotAffectOther() external whenVerifyingFullAttackScenario {
        // Both users install policy
        _installPolicy(WALLET, POLICY_ID_1);
        _installPolicy(WALLET2, POLICY_ID_1);

        // Both users create and approve proposals
        bytes memory callData1 = hex"1111";
        bytes memory callData2 = hex"2222";

        _createProposal(WALLET, POLICY_ID_1, callData1, 1);
        _approveProposal(WALLET, POLICY_ID_1, callData1, 1);
        _createProposal(WALLET2, POLICY_ID_1, callData2, 1);
        _approveProposal(WALLET2, POLICY_ID_1, callData2, 1);

        vm.warp(block.timestamp + DELAY + 1);

        // WALLET reinstalls
        _uninstallPolicy(WALLET, POLICY_ID_1);
        _installPolicy(WALLET, POLICY_ID_1);

        // it should only affect that users epoch
        assertEq(timelockPolicy.currentEpoch(POLICY_ID_1, WALLET), 2, "WALLET should be epoch 2");
        assertEq(timelockPolicy.currentEpoch(POLICY_ID_1, WALLET2), 1, "WALLET2 should still be epoch 1");

        // WALLET's old proposal should fail (epoch mismatch)
        PackedUserOperation memory userOp1 = _createUserOp(WALLET, callData1, 1);
        vm.prank(WALLET);
        uint256 result1 = timelockPolicy.checkUserOpPolicy(POLICY_ID_1, userOp1);
        assertEq(result1, SIG_VALIDATION_FAILED_UINT, "WALLET's old proposal should fail");

        // it should not affect other users proposals
        PackedUserOperation memory userOp2 = _createUserOp(WALLET2, callData2, 1);
        vm.prank(WALLET2);
        uint256 result2 = timelockPolicy.checkUserOpPolicy(POLICY_ID_1, userOp2);
        assertTrue(result2 != SIG_VALIDATION_FAILED_UINT, "WALLET2's proposal should still work");
    }
}
