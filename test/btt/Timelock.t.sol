// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {TimelockPolicy} from "src/policies/TimelockPolicy.sol";
import {AtomicCallHarness} from "test/utils/AtomicCallHarness.sol";
import {MockTimelockEntryPoint} from "test/utils/MockTimelockEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IAccountExecute} from "account-abstraction/interfaces/IAccountExecute.sol";
import {IERC7579Execution} from "openzeppelin-contracts/contracts/interfaces/draft-IERC7579.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";
import {IModule} from "src/interfaces/IERC7579Modules.sol";
import {
    MODULE_TYPE_POLICY,
    MODULE_TYPE_STATELESS_VALIDATOR,
    MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER
} from "src/types/Constants.sol";

/**
 * @title TimelockTest
 * @notice Tests the authenticated, sponsored proposal-creation flow.
 */
contract TimelockTest is Test {
    TimelockPolicy internal timelockPolicy;
    MockTimelockEntryPoint internal entryPoint;

    address internal constant WALLET = address(0x1234);
    address internal constant SECOND_WALLET = address(0x5678);
    address internal constant ATTACKER = address(0xDEAD);
    address internal constant GUARDIAN = address(0xBEEF);
    address internal constant PAYMASTER = address(0xCAFE);

    bytes32 internal constant POLICY_ID = bytes32(uint256(1));
    bytes32 internal constant OTHER_POLICY_ID = bytes32(uint256(2));
    uint48 internal constant DELAY = 1 hours;
    uint48 internal constant EXPIRATION = 1 days;
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    function setUp() public {
        timelockPolicy = new TimelockPolicy();
        entryPoint = new MockTimelockEntryPoint();
        AtomicCallHarness harness = new AtomicCallHarness();
        vm.etch(WALLET, address(harness).code);
        vm.etch(SECOND_WALLET, address(harness).code);
        _install(WALLET, POLICY_ID, address(0));
    }

    function _install(address wallet, bytes32 id, address guardian) internal {
        vm.prank(wallet);
        timelockPolicy.onInstall(abi.encode(id, DELAY, EXPIRATION, guardian, address(entryPoint)));
    }

    function _paymasterAndData() internal pure returns (bytes memory) {
        return abi.encodePacked(PAYMASTER, uint128(300_000), uint128(100_000));
    }

    function _userOp(address sender, bytes memory callData, uint256 nonce, bytes memory paymasterAndData)
        internal
        pure
        returns (PackedUserOperation memory)
    {
        return PackedUserOperation({
            sender: sender,
            nonce: nonce,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(100_000), uint128(200_000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: paymasterAndData,
            signature: "authenticated-by-permission-signer"
        });
    }

    function _creationOp(
        address wallet,
        bytes32 id,
        bytes memory proposalCallData,
        uint256 proposalNonce,
        bytes memory paymasterAndData
    ) internal view returns (PackedUserOperation memory) {
        return _userOp(
            wallet, timelockPolicy.getProposalCreationCallData(id, proposalCallData, proposalNonce), 0, paymasterAndData
        );
    }

    function _executionOp(address wallet, bytes memory callData, uint256 nonce)
        internal
        pure
        returns (PackedUserOperation memory)
    {
        return _userOp(wallet, callData, nonce, "");
    }

    function _key(address wallet, bytes memory callData, uint256 nonce) internal view returns (bytes32) {
        return timelockPolicy.computeUserOpKey(wallet, callData, nonce);
    }

    function _currentUserOpHash(address) internal view returns (bytes32) {
        return entryPoint.getCurrentUserOpHash();
    }

    function _userOpHash(address wallet, bytes32 id, PackedUserOperation memory userOp)
        internal
        view
        returns (bytes32)
    {
        return timelockPolicy.getEntryPointUserOpHash(id, wallet, userOp);
    }

    function _commit(address wallet, bytes32 id, bytes memory callData, uint256 nonce) internal returns (bytes32 key) {
        PackedUserOperation memory creationOp = _creationOp(wallet, id, callData, nonce, _paymasterAndData());
        key = _key(wallet, callData, nonce);
        bytes32 userOpHash = _userOpHash(wallet, id, creationOp);

        AtomicCallHarness.Call[] memory calls = new AtomicCallHarness.Call[](3);
        calls[0] = AtomicCallHarness.Call({
            target: address(timelockPolicy), data: abi.encodeCall(timelockPolicy.checkUserOpPolicy, (id, creationOp))
        });
        calls[1] = AtomicCallHarness.Call({
            target: address(entryPoint), data: abi.encodeCall(entryPoint.setCurrentUserOpHash, (userOpHash))
        });
        calls[2] = AtomicCallHarness.Call({
            target: address(timelockPolicy),
            data: abi.encodeCall(timelockPolicy.proposalCommitments, (userOpHash, key, id, wallet))
        });
        (bool[] memory successes, bytes[] memory results) = AtomicCallHarness(wallet).execute(calls);

        assertTrue(successes[0], "creation validation reverted");
        assertEq(abi.decode(results[0], (uint256)), 0, "creation validation should commit");
        assertTrue(successes[1], "EntryPoint hash update reverted");
        assertTrue(successes[2], "commitment read reverted");
        assertEq(
            abi.decode(results[2], (uint256)),
            timelockPolicy.currentEpoch(id, wallet),
            "commitment should contain the current epoch"
        );
    }

    function _create(address wallet, bytes32 id, bytes memory callData, uint256 nonce) internal returns (bytes32 key) {
        PackedUserOperation memory creationOp = _creationOp(wallet, id, callData, nonce, _paymasterAndData());
        key = _key(wallet, callData, nonce);
        bytes32 userOpHash = _userOpHash(wallet, id, creationOp);

        AtomicCallHarness.Call[] memory calls = new AtomicCallHarness.Call[](4);
        calls[0] = AtomicCallHarness.Call({
            target: address(timelockPolicy), data: abi.encodeCall(timelockPolicy.checkUserOpPolicy, (id, creationOp))
        });
        calls[1] = AtomicCallHarness.Call({
            target: address(entryPoint), data: abi.encodeCall(entryPoint.setCurrentUserOpHash, (userOpHash))
        });
        calls[2] = AtomicCallHarness.Call({
            target: address(timelockPolicy), data: abi.encodeCall(timelockPolicy.createProposal, (id, callData, nonce))
        });
        calls[3] = AtomicCallHarness.Call({
            target: address(timelockPolicy),
            data: abi.encodeCall(timelockPolicy.proposalCommitments, (userOpHash, key, id, wallet))
        });
        (bool[] memory successes, bytes[] memory results) = AtomicCallHarness(wallet).execute(calls);

        assertTrue(successes[0], "creation validation reverted");
        assertEq(abi.decode(results[0], (uint256)), 0, "creation validation should commit");
        assertTrue(successes[1], "EntryPoint hash update reverted");
        assertTrue(successes[2], "proposal creation reverted");
        assertTrue(successes[3], "commitment read reverted");
        assertEq(abi.decode(results[3], (uint256)), 0, "commitment should be consumed");
    }

    function _status(address wallet, bytes32 id, bytes memory callData, uint256 nonce)
        internal
        view
        returns (TimelockPolicy.ProposalStatus status)
    {
        (status,,) = timelockPolicy.getProposal(wallet, callData, nonce, id, wallet);
    }

    function _packValidationData(uint48 validAfter, uint48 validUntil) internal pure returns (uint256) {
        return uint256(validAfter) << 208 | uint256(validUntil) << 160;
    }

    function test_InstallStoresConfigAndIncrementsEpoch() external {
        _install(SECOND_WALLET, OTHER_POLICY_ID, GUARDIAN);

        (uint48 delay, uint48 expiration, address guardian, bool initialized) =
            timelockPolicy.timelockConfig(OTHER_POLICY_ID, SECOND_WALLET);
        assertEq(delay, DELAY);
        assertEq(expiration, EXPIRATION);
        assertEq(guardian, GUARDIAN);
        assertTrue(initialized);
        assertEq(timelockPolicy.currentEpoch(OTHER_POLICY_ID, SECOND_WALLET), 1);
    }

    function test_InstallRejectsInvalidConfigurationAndDuplicateInstall() external {
        vm.prank(SECOND_WALLET);
        vm.expectRevert(TimelockPolicy.InvalidDelay.selector);
        timelockPolicy.onInstall(abi.encode(OTHER_POLICY_ID, uint48(0), EXPIRATION, address(0)));

        vm.prank(SECOND_WALLET);
        vm.expectRevert(TimelockPolicy.InvalidExpirationPeriod.selector);
        timelockPolicy.onInstall(abi.encode(OTHER_POLICY_ID, DELAY, uint48(0), address(0)));

        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IModule.AlreadyInitialized.selector, WALLET));
        timelockPolicy.onInstall(abi.encode(POLICY_ID, DELAY, EXPIRATION, address(0)));
    }

    function test_UninstallClearsConfigButPreservesEpoch() external {
        assertEq(timelockPolicy.currentEpoch(POLICY_ID, WALLET), 1);

        vm.prank(WALLET);
        timelockPolicy.onUninstall(abi.encode(POLICY_ID));

        (,,, bool initialized) = timelockPolicy.timelockConfig(POLICY_ID, WALLET);
        assertFalse(initialized);
        assertEq(timelockPolicy.currentEpoch(POLICY_ID, WALLET), 1);
    }

    function test_OnlyPolicyModuleTypeIsAdvertised() external view {
        assertTrue(timelockPolicy.isModuleType(MODULE_TYPE_POLICY));
        assertFalse(timelockPolicy.isModuleType(MODULE_TYPE_STATELESS_VALIDATOR));
        assertFalse(timelockPolicy.isModuleType(MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER));
        assertFalse(timelockPolicy.isModuleType(999));
    }

    function test_StatelessAndSignatureValidationRevert() external {
        vm.expectRevert(TimelockPolicy.StatelessValidationNotSupported.selector);
        timelockPolicy.validateSignatureWithData(bytes32(0), "", "");

        vm.expectRevert(TimelockPolicy.StatelessValidationNotSupported.selector);
        timelockPolicy.validateSignatureWithDataWithSender(WALLET, bytes32(0), "", "");

        vm.expectRevert(TimelockPolicy.SignatureValidationNotSupported.selector);
        timelockPolicy.checkSignaturePolicy(POLICY_ID, WALLET, bytes32(0), "");
    }

    function test_GetProposalCreationCallDataReturnsCanonicalERC7579Call() external view {
        bytes memory proposalCallData = hex"1234abcd";
        uint256 proposalNonce = 17;
        bytes memory actual = timelockPolicy.getProposalCreationCallData(POLICY_ID, proposalCallData, proposalNonce);

        bytes32 mode =
            LibERC7579.encodeMode(LibERC7579.CALLTYPE_SINGLE, LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes22(0));
        bytes memory inner = abi.encodeCall(timelockPolicy.createProposal, (POLICY_ID, proposalCallData, proposalNonce));
        bytes memory expected = abi.encodePacked(
            IAccountExecute.executeUserOp.selector,
            abi.encodeWithSelector(
                IERC7579Execution.execute.selector, mode, abi.encodePacked(address(timelockPolicy), uint256(0), inner)
            )
        );

        assertEq(actual, expected);
    }

    function test_CanonicalSponsoredCreationCommitsExactProposal() external {
        bytes memory callData = hex"01020304";
        uint256 nonce = 41;
        bytes32 key = _key(WALLET, callData, nonce);
        PackedUserOperation memory creationOp = _creationOp(WALLET, POLICY_ID, callData, nonce, _paymasterAndData());
        bytes32 userOpHash = _userOpHash(WALLET, POLICY_ID, creationOp);

        vm.expectEmit(true, true, true, true);
        emit TimelockPolicy.ProposalCommitted(WALLET, POLICY_ID, key, userOpHash, 1);
        _commit(WALLET, POLICY_ID, callData, nonce);

        assertEq(uint256(_status(WALLET, POLICY_ID, callData, nonce)), uint256(TimelockPolicy.ProposalStatus.None));
    }

    function test_CreationRequiresNonzeroPaymasterAndCompletePaymasterData() external {
        bytes memory callData = hex"1111";
        uint256 nonce = 42;

        PackedUserOperation memory noPaymaster = _creationOp(WALLET, POLICY_ID, callData, nonce, "");
        vm.prank(WALLET);
        assertEq(timelockPolicy.checkUserOpPolicy(POLICY_ID, noPaymaster), SIG_VALIDATION_FAILED);

        PackedUserOperation memory shortPaymaster =
            _creationOp(WALLET, POLICY_ID, callData, nonce, abi.encodePacked(PAYMASTER, bytes31(0)));
        vm.prank(WALLET);
        assertEq(timelockPolicy.checkUserOpPolicy(POLICY_ID, shortPaymaster), SIG_VALIDATION_FAILED);

        PackedUserOperation memory zeroPaymaster = _creationOp(
            WALLET, POLICY_ID, callData, nonce, abi.encodePacked(address(0), uint128(300_000), uint128(100_000))
        );
        vm.prank(WALLET);
        assertEq(timelockPolicy.checkUserOpPolicy(POLICY_ID, zeroPaymaster), SIG_VALIDATION_FAILED);

        assertEq(
            timelockPolicy.proposalCommitments(
                _currentUserOpHash(WALLET), _key(WALLET, callData, nonce), POLICY_ID, WALLET
            ),
            0
        );
    }

    function test_LegacyUnsignedNoOpDoesNotCreateProposal() external {
        bytes memory callData = hex"deadbeef";
        uint256 nonce = 99;
        bytes memory legacySignature = abi.encodePacked(bytes32(callData.length), callData, bytes32(nonce), bytes1(0));
        PackedUserOperation memory noOp = _userOp(WALLET, "", 0, _paymasterAndData());
        noOp.signature = legacySignature;

        vm.prank(WALLET);
        assertEq(timelockPolicy.checkUserOpPolicy(POLICY_ID, noOp), SIG_VALIDATION_FAILED);
        assertEq(uint256(_status(WALLET, POLICY_ID, callData, nonce)), uint256(TimelockPolicy.ProposalStatus.None));
        assertEq(
            timelockPolicy.proposalCommitments(
                _currentUserOpHash(WALLET), _key(WALLET, callData, nonce), POLICY_ID, WALLET
            ),
            0
        );
    }

    function test_CreationRejectsWrongPolicySenderAndCaller() external {
        bytes memory callData = hex"2222";
        uint256 nonce = 7;

        PackedUserOperation memory wrongId = _creationOp(WALLET, OTHER_POLICY_ID, callData, nonce, _paymasterAndData());
        vm.prank(WALLET);
        assertEq(timelockPolicy.checkUserOpPolicy(POLICY_ID, wrongId), SIG_VALIDATION_FAILED);

        PackedUserOperation memory wrongSender = _creationOp(WALLET, POLICY_ID, callData, nonce, _paymasterAndData());
        wrongSender.sender = ATTACKER;
        vm.prank(WALLET);
        assertEq(timelockPolicy.checkUserOpPolicy(POLICY_ID, wrongSender), SIG_VALIDATION_FAILED);

        PackedUserOperation memory wrongCaller = _creationOp(WALLET, POLICY_ID, callData, nonce, _paymasterAndData());
        vm.prank(ATTACKER);
        assertEq(timelockPolicy.checkUserOpPolicy(POLICY_ID, wrongCaller), SIG_VALIDATION_FAILED);
    }

    function test_CreationRejectsNoncanonicalTrailingData() external {
        bytes memory callData = hex"3333";
        uint256 nonce = 8;
        bytes memory canonical = timelockPolicy.getProposalCreationCallData(POLICY_ID, callData, nonce);
        PackedUserOperation memory malformed = _userOp(WALLET, bytes.concat(canonical, hex"00"), 0, _paymasterAndData());

        vm.prank(WALLET);
        assertEq(timelockPolicy.checkUserOpPolicy(POLICY_ID, malformed), SIG_VALIDATION_FAILED);
        assertEq(
            timelockPolicy.proposalCommitments(
                _currentUserOpHash(WALLET), _key(WALLET, callData, nonce), POLICY_ID, WALLET
            ),
            0
        );
    }

    function test_CreateProposalRequiresPriorCommitment() external {
        vm.prank(WALLET);
        vm.expectRevert(TimelockPolicy.MissingProposalCommitment.selector);
        timelockPolicy.createProposal(POLICY_ID, hex"4444", 9);
    }

    function test_CommitmentBindsCallDataAndNonce() external {
        bytes memory callData = hex"5555";
        uint256 nonce = 10;
        PackedUserOperation memory creationOp = _creationOp(WALLET, POLICY_ID, callData, nonce, _paymasterAndData());
        bytes32 userOpHash = _userOpHash(WALLET, POLICY_ID, creationOp);

        AtomicCallHarness.Call[] memory calls = new AtomicCallHarness.Call[](5);
        calls[0] = AtomicCallHarness.Call({
            target: address(timelockPolicy),
            data: abi.encodeCall(timelockPolicy.checkUserOpPolicy, (POLICY_ID, creationOp))
        });
        calls[1] = AtomicCallHarness.Call({
            target: address(entryPoint), data: abi.encodeCall(entryPoint.setCurrentUserOpHash, (userOpHash))
        });
        calls[2] = AtomicCallHarness.Call({
            target: address(timelockPolicy),
            data: abi.encodeCall(timelockPolicy.createProposal, (POLICY_ID, hex"555500", nonce))
        });
        calls[3] = AtomicCallHarness.Call({
            target: address(timelockPolicy),
            data: abi.encodeCall(timelockPolicy.createProposal, (POLICY_ID, callData, nonce + 1))
        });
        calls[4] = AtomicCallHarness.Call({
            target: address(timelockPolicy),
            data: abi.encodeCall(timelockPolicy.createProposal, (POLICY_ID, callData, nonce))
        });
        (bool[] memory successes, bytes[] memory results) = AtomicCallHarness(WALLET).execute(calls);

        assertTrue(successes[0]);
        assertEq(abi.decode(results[0], (uint256)), 0);
        assertTrue(successes[1]);
        assertFalse(successes[2]);
        assertEq(bytes4(results[2]), TimelockPolicy.MissingProposalCommitment.selector);
        assertFalse(successes[3]);
        assertEq(bytes4(results[3]), TimelockPolicy.MissingProposalCommitment.selector);
        assertTrue(successes[4]);
        assertEq(uint256(_status(WALLET, POLICY_ID, callData, nonce)), uint256(TimelockPolicy.ProposalStatus.Pending));
    }

    function test_CommitmentIsConsumedExactlyOnce() external {
        bytes memory callData = hex"6666";
        uint256 nonce = 11;
        bytes32 key = _create(WALLET, POLICY_ID, callData, nonce);
        assertEq(timelockPolicy.proposalCommitments(_currentUserOpHash(WALLET), key, POLICY_ID, WALLET), 0);

        vm.prank(WALLET);
        vm.expectRevert(TimelockPolicy.MissingProposalCommitment.selector);
        timelockPolicy.createProposal(POLICY_ID, callData, nonce);
    }

    function test_ProposalClockStartsWhenAtomicCreationExecutes() external {
        bytes memory callData = hex"7777";
        uint256 nonce = 12;
        vm.warp(20_000);
        _create(WALLET, POLICY_ID, callData, nonce);

        (, uint256 validAfter, uint256 validUntil) =
            timelockPolicy.getProposal(WALLET, callData, nonce, POLICY_ID, WALLET);
        assertEq(validAfter, 20_000 + DELAY);
        assertEq(validUntil, 20_000 + DELAY + EXPIRATION);
    }

    function test_ExecutionReturnsStoredWindowAndConsumesProposal() external {
        bytes memory callData = hex"8888";
        uint256 nonce = 13;
        _create(WALLET, POLICY_ID, callData, nonce);
        (, uint256 validAfter, uint256 validUntil) =
            timelockPolicy.getProposal(WALLET, callData, nonce, POLICY_ID, WALLET);
        vm.warp(validAfter);

        PackedUserOperation memory executionOp = _executionOp(WALLET, callData, nonce);
        vm.prank(WALLET);
        uint256 validationData = timelockPolicy.checkUserOpPolicy(POLICY_ID, executionOp);

        assertEq(validationData, _packValidationData(uint48(validAfter), uint48(validUntil)));
        assertEq(uint256(_status(WALLET, POLICY_ID, callData, nonce)), uint256(TimelockPolicy.ProposalStatus.Executed));

        vm.prank(WALLET);
        assertEq(timelockPolicy.checkUserOpPolicy(POLICY_ID, executionOp), SIG_VALIDATION_FAILED);
    }

    function test_OwnerAndGuardianCanCancelButAttackerCannot() external {
        _install(SECOND_WALLET, POLICY_ID, GUARDIAN);
        bytes memory ownerCall = hex"9999";
        bytes memory guardianCall = hex"aaaa";
        _create(SECOND_WALLET, POLICY_ID, ownerCall, 14);
        _create(SECOND_WALLET, POLICY_ID, guardianCall, 15);

        vm.prank(ATTACKER);
        vm.expectRevert(TimelockPolicy.OnlyAccount.selector);
        timelockPolicy.cancelProposal(POLICY_ID, SECOND_WALLET, ownerCall, 14);

        vm.prank(SECOND_WALLET);
        timelockPolicy.cancelProposal(POLICY_ID, SECOND_WALLET, ownerCall, 14);
        assertEq(
            uint256(_status(SECOND_WALLET, POLICY_ID, ownerCall, 14)), uint256(TimelockPolicy.ProposalStatus.Cancelled)
        );

        vm.prank(GUARDIAN);
        timelockPolicy.cancelProposal(POLICY_ID, SECOND_WALLET, guardianCall, 15);
        assertEq(
            uint256(_status(SECOND_WALLET, POLICY_ID, guardianCall, 15)),
            uint256(TimelockPolicy.ProposalStatus.Cancelled)
        );
    }

    function test_CancellationWinsRaceWhenProcessedFirst() external {
        bytes memory callData = hex"bbbb";
        uint256 nonce = 16;
        _create(WALLET, POLICY_ID, callData, nonce);

        vm.prank(WALLET);
        timelockPolicy.cancelProposal(POLICY_ID, WALLET, callData, nonce);

        PackedUserOperation memory executionOp = _executionOp(WALLET, callData, nonce);
        vm.prank(WALLET);
        assertEq(timelockPolicy.checkUserOpPolicy(POLICY_ID, executionOp), SIG_VALIDATION_FAILED);
        assertEq(uint256(_status(WALLET, POLICY_ID, callData, nonce)), uint256(TimelockPolicy.ProposalStatus.Cancelled));
    }

    function test_ExecutionWinsRaceWhenProcessedFirst() external {
        bytes memory callData = hex"cccc";
        uint256 nonce = 17;
        _create(WALLET, POLICY_ID, callData, nonce);

        PackedUserOperation memory executionOp = _executionOp(WALLET, callData, nonce);
        vm.prank(WALLET);
        assertNotEq(timelockPolicy.checkUserOpPolicy(POLICY_ID, executionOp), SIG_VALIDATION_FAILED);

        vm.prank(WALLET);
        vm.expectRevert(TimelockPolicy.ProposalNotPending.selector);
        timelockPolicy.cancelProposal(POLICY_ID, WALLET, callData, nonce);
        assertEq(uint256(_status(WALLET, POLICY_ID, callData, nonce)), uint256(TimelockPolicy.ProposalStatus.Executed));
    }

    function test_CanonicalCreationCannotReplacePendingCancelledOrExecutedProposal() external {
        bytes memory pendingCall = hex"d001";
        bytes memory cancelledCall = hex"d002";
        bytes memory executedCall = hex"d003";
        _create(WALLET, POLICY_ID, pendingCall, 18);
        _create(WALLET, POLICY_ID, cancelledCall, 19);
        _create(WALLET, POLICY_ID, executedCall, 20);

        vm.prank(WALLET);
        timelockPolicy.cancelProposal(POLICY_ID, WALLET, cancelledCall, 19);
        vm.prank(WALLET);
        timelockPolicy.checkUserOpPolicy(POLICY_ID, _executionOp(WALLET, executedCall, 20));

        PackedUserOperation memory pendingRetry = _creationOp(WALLET, POLICY_ID, pendingCall, 18, _paymasterAndData());
        PackedUserOperation memory cancelledRetry =
            _creationOp(WALLET, POLICY_ID, cancelledCall, 19, _paymasterAndData());
        PackedUserOperation memory executedRetry = _creationOp(WALLET, POLICY_ID, executedCall, 20, _paymasterAndData());

        vm.startPrank(WALLET);
        assertEq(timelockPolicy.checkUserOpPolicy(POLICY_ID, pendingRetry), SIG_VALIDATION_FAILED);
        assertEq(timelockPolicy.checkUserOpPolicy(POLICY_ID, cancelledRetry), SIG_VALIDATION_FAILED);
        assertEq(timelockPolicy.checkUserOpPolicy(POLICY_ID, executedRetry), SIG_VALIDATION_FAILED);
        vm.stopPrank();
    }
}
