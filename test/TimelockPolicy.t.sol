// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {TimelockPolicy} from "src/policies/TimelockPolicy.sol";
import {AtomicCallHarness} from "test/utils/AtomicCallHarness.sol";
import {MockTimelockEntryPoint} from "test/utils/MockTimelockEntryPoint.sol";
import {IStatelessValidator, IStatelessValidatorWithSender} from "src/interfaces/IERC7579Modules.sol";
import {
    MODULE_TYPE_POLICY,
    MODULE_TYPE_STATELESS_VALIDATOR,
    MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER,
    SIG_VALIDATION_FAILED_UINT,
    SIG_VALIDATION_SUCCESS_UINT
} from "src/types/Constants.sol";

contract TimelockPolicySlotHarness is TimelockPolicy {
    function proposalCommitmentSlot(bytes32 creationUserOpHash, bytes32 userOpKey, bytes32 id, address account)
        external
        pure
        returns (bytes32)
    {
        return _proposalCommitmentSlot(creationUserOpHash, userOpKey, id, account);
    }
}

contract TimelockPolicyTest is Test {
    TimelockPolicy internal policy;
    MockTimelockEntryPoint internal entryPoint;

    address internal constant WALLET = address(0x1234);
    address internal constant GUARDIAN = address(0xBEEF);
    address internal constant PAYMASTER = address(0xCAFE);
    bytes32 internal constant POLICY_ID = keccak256("POLICY_ID");
    uint48 internal constant DELAY = 1 days;
    uint48 internal constant EXPIRATION = 2 days;

    function setUp() public {
        policy = new TimelockPolicy();
        entryPoint = new MockTimelockEntryPoint();
        AtomicCallHarness harness = new AtomicCallHarness();
        vm.etch(WALLET, address(harness).code);
        vm.prank(WALLET);
        policy.onInstall(abi.encode(POLICY_ID, DELAY, EXPIRATION, GUARDIAN, address(entryPoint)));
    }

    function _paymasterData() internal pure returns (bytes memory) {
        return abi.encodePacked(PAYMASTER, uint128(300_000), uint128(100_000));
    }

    function _creationOp(bytes memory proposalCallData, uint256 proposalNonce, bytes memory paymasterAndData)
        internal
        view
        returns (PackedUserOperation memory)
    {
        return PackedUserOperation({
            sender: WALLET,
            nonce: 0,
            initCode: "",
            callData: policy.getProposalCreationCallData(POLICY_ID, proposalCallData, proposalNonce),
            accountGasLimits: bytes32(abi.encodePacked(uint128(300_000), uint128(300_000))),
            preVerificationGas: 100_000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: paymasterAndData,
            signature: "policy-slice-is-ignored"
        });
    }

    function _executionOp(bytes memory callData, uint256 nonce) internal pure returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: WALLET,
            nonce: nonce,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(300_000), uint128(300_000))),
            preVerificationGas: 100_000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: "",
            signature: ""
        });
    }

    function _commitAndCreate(bytes memory proposalCallData, uint256 proposalNonce) internal {
        PackedUserOperation memory creation = _creationOp(proposalCallData, proposalNonce, _paymasterData());
        AtomicCallHarness.Call[] memory calls = new AtomicCallHarness.Call[](3);
        calls[0] = AtomicCallHarness.Call({
            target: address(policy), data: abi.encodeCall(policy.checkUserOpPolicy, (POLICY_ID, creation))
        });
        calls[1] = AtomicCallHarness.Call({
            target: address(entryPoint), data: abi.encodeCall(entryPoint.setCurrentUserOpHash, (_userOpHash(creation)))
        });
        calls[2] = AtomicCallHarness.Call({
            target: address(policy),
            data: abi.encodeCall(policy.createProposal, (POLICY_ID, proposalCallData, proposalNonce))
        });

        (bool[] memory successes, bytes[] memory results) = AtomicCallHarness(WALLET).execute(calls);
        assertTrue(successes[0], "creation validation reverted");
        assertEq(abi.decode(results[0], (uint256)), SIG_VALIDATION_SUCCESS_UINT);
        assertTrue(successes[1], "EntryPoint hash update reverted");
        assertTrue(successes[2], "proposal creation reverted");
    }

    function _userOpHash(PackedUserOperation memory userOp) internal view returns (bytes32) {
        return policy.getEntryPointUserOpHash(POLICY_ID, WALLET, userOp);
    }

    function test_installStoresConfigAndAdvancesEpoch() public view {
        (uint48 delay, uint48 expiration, address guardian, bool initialized) = policy.timelockConfig(POLICY_ID, WALLET);
        assertEq(delay, DELAY);
        assertEq(expiration, EXPIRATION);
        assertEq(guardian, GUARDIAN);
        assertTrue(initialized);
        assertEq(policy.currentEpoch(POLICY_ID, WALLET), 1);
        assertEq(policy.configuredEntryPoint(POLICY_ID, WALLET), address(entryPoint));
    }

    function test_legacyInstallUsesOfficialEntryPointV09() public {
        address secondWallet = address(0x5678);
        bytes32 secondId = keccak256("SECOND_POLICY_ID");
        vm.prank(secondWallet);
        policy.onInstall(abi.encode(secondId, DELAY, EXPIRATION, GUARDIAN));

        assertEq(policy.DEFAULT_ENTRYPOINT_V09(), 0x433709009B8330FDa32311DF1C2AFA402eD8D009);
        assertEq(policy.configuredEntryPoint(secondId, secondWallet), policy.DEFAULT_ENTRYPOINT_V09());
    }

    function test_extendedInstallRejectsZeroEntryPoint() public {
        vm.prank(address(0x5678));
        vm.expectRevert(TimelockPolicy.InvalidEntryPoint.selector);
        policy.onInstall(abi.encode(keccak256("SECOND_POLICY_ID"), DELAY, EXPIRATION, GUARDIAN, address(0)));
    }

    function test_commitmentSlotUsesERC7562AssociatedStorageShape() public {
        TimelockPolicySlotHarness harness = new TimelockPolicySlotHarness();
        bytes32 creationUserOpHash = keccak256("creation UserOp");
        bytes32 userOpKey = keccak256("proposal key");
        bytes32 subkey = keccak256(
            abi.encode(
                keccak256("kernel.7579.plugins.TimelockPolicy.proposalCommitment"),
                creationUserOpHash,
                userOpKey,
                POLICY_ID
            )
        );

        assertEq(
            harness.proposalCommitmentSlot(creationUserOpHash, userOpKey, POLICY_ID, WALLET),
            keccak256(abi.encode(WALLET, subkey))
        );
    }

    function test_moduleTypesAreTruthful() public view {
        assertTrue(policy.isModuleType(MODULE_TYPE_POLICY));
        assertFalse(policy.isModuleType(MODULE_TYPE_STATELESS_VALIDATOR));
        assertFalse(policy.isModuleType(MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER));
    }

    function testFuzz_onlyPolicyModuleTypeIsAdvertised(uint256 moduleType) public view {
        assertEq(policy.isModuleType(moduleType), moduleType == MODULE_TYPE_POLICY);
    }

    function test_creationRequiresPaymaster() public {
        bytes memory proposed = hex"12345678";
        PackedUserOperation memory creation = _creationOp(proposed, 1, "");
        vm.prank(WALLET);
        assertEq(policy.checkUserOpPolicy(POLICY_ID, creation), SIG_VALIDATION_FAILED_UINT);
        vm.prank(WALLET);
        vm.expectRevert(TimelockPolicy.MissingProposalCommitment.selector);
        policy.createProposal(POLICY_ID, proposed, 1);
    }

    function test_creationRejectsShortAndZeroPaymasterData() public {
        bytes memory proposed = hex"12345678";
        PackedUserOperation memory creation = _creationOp(proposed, 1, abi.encodePacked(PAYMASTER));
        vm.prank(WALLET);
        assertEq(policy.checkUserOpPolicy(POLICY_ID, creation), SIG_VALIDATION_FAILED_UINT);
        creation.paymasterAndData = abi.encodePacked(address(0), uint128(1), uint128(1));
        vm.prank(WALLET);
        assertEq(policy.checkUserOpPolicy(POLICY_ID, creation), SIG_VALIDATION_FAILED_UINT);
    }

    function test_creationRejectsNonemptyInitCode() public {
        PackedUserOperation memory creation = _creationOp(hex"12345678", 1, _paymasterData());
        creation.initCode = hex"7702";
        vm.prank(WALLET);
        assertEq(policy.checkUserOpPolicy(POLICY_ID, creation), SIG_VALIDATION_FAILED_UINT);
    }

    function test_legacyUnsignedSignatureProposalIsRejected() public {
        bytes memory proposed = hex"12345678";
        PackedUserOperation memory legacy = _executionOp("", 0);
        legacy.paymasterAndData = _paymasterData();
        legacy.signature = abi.encodePacked(bytes32(proposed.length), proposed, bytes32(uint256(1)));
        vm.prank(WALLET);
        assertEq(policy.checkUserOpPolicy(POLICY_ID, legacy), SIG_VALIDATION_FAILED_UINT);
    }

    function test_createProposalRequiresValidationCommitment() public {
        vm.prank(WALLET);
        vm.expectRevert(TimelockPolicy.MissingProposalCommitment.selector);
        policy.createProposal(POLICY_ID, hex"1234", 1);
    }

    function test_creationStartsDelayDuringAtomicExecution() public {
        bytes memory proposed = hex"12345678";
        uint256 executionTime = vm.getBlockTimestamp();
        _commitAndCreate(proposed, 7);

        (TimelockPolicy.ProposalStatus status, uint256 validAfter, uint256 validUntil) =
            policy.getProposal(WALLET, proposed, 7, POLICY_ID, WALLET);
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Pending));
        assertEq(validAfter, executionTime + DELAY);
        assertEq(validUntil, executionTime + DELAY + EXPIRATION);
    }

    function testFuzz_authenticatedProposalIsBoundAndClockStartsAtExecution(
        bytes calldata proposed,
        uint256 proposalNonce,
        address sponsor,
        uint48 rawWait
    ) public {
        vm.assume(sponsor != address(0));
        uint48 wait = uint48(bound(rawWait, 1, 30 days));
        uint256 validationTime = vm.getBlockTimestamp();
        vm.warp(validationTime + wait);
        uint256 executionTime = vm.getBlockTimestamp();
        PackedUserOperation memory creation =
            _creationOp(proposed, proposalNonce, abi.encodePacked(sponsor, uint128(300_000), uint128(100_000)));
        bytes memory tampered = abi.encodePacked(proposed, bytes1(0x01));

        AtomicCallHarness.Call[] memory calls = new AtomicCallHarness.Call[](5);
        calls[0] = AtomicCallHarness.Call({
            target: address(policy), data: abi.encodeCall(policy.checkUserOpPolicy, (POLICY_ID, creation))
        });
        calls[1] = AtomicCallHarness.Call({
            target: address(entryPoint), data: abi.encodeCall(entryPoint.setCurrentUserOpHash, (_userOpHash(creation)))
        });
        calls[2] = AtomicCallHarness.Call({
            target: address(policy), data: abi.encodeCall(policy.createProposal, (POLICY_ID, tampered, proposalNonce))
        });
        calls[3] = AtomicCallHarness.Call({
            target: address(policy), data: abi.encodeCall(policy.createProposal, (POLICY_ID, proposed, proposalNonce))
        });
        calls[4] = calls[3];
        (bool[] memory successes, bytes[] memory results) = AtomicCallHarness(WALLET).execute(calls);

        assertTrue(successes[0]);
        assertEq(abi.decode(results[0], (uint256)), SIG_VALIDATION_SUCCESS_UINT);
        assertTrue(successes[1]);
        assertFalse(successes[2]);
        assertEq(bytes4(results[2]), TimelockPolicy.MissingProposalCommitment.selector);
        assertTrue(successes[3]);
        assertFalse(successes[4]);
        assertEq(bytes4(results[4]), TimelockPolicy.MissingProposalCommitment.selector);

        (TimelockPolicy.ProposalStatus status, uint256 validAfter, uint256 validUntil) =
            policy.getProposal(WALLET, proposed, proposalNonce, POLICY_ID, WALLET);
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Pending));
        assertEq(validAfter, executionTime + DELAY);
        assertEq(validUntil, executionTime + DELAY + EXPIRATION);
    }

    function test_commitmentCannotBeUsedForDifferentProposal() public {
        PackedUserOperation memory creation = _creationOp(hex"aaaa", 3, _paymasterData());
        AtomicCallHarness.Call[] memory calls = new AtomicCallHarness.Call[](3);
        calls[0] = AtomicCallHarness.Call({
            target: address(policy), data: abi.encodeCall(policy.checkUserOpPolicy, (POLICY_ID, creation))
        });
        calls[1] = AtomicCallHarness.Call({
            target: address(entryPoint), data: abi.encodeCall(entryPoint.setCurrentUserOpHash, (_userOpHash(creation)))
        });
        calls[2] = AtomicCallHarness.Call({
            target: address(policy), data: abi.encodeCall(policy.createProposal, (POLICY_ID, hex"bbbb", 3))
        });
        (bool[] memory successes, bytes[] memory results) = AtomicCallHarness(WALLET).execute(calls);
        assertTrue(successes[0]);
        assertEq(abi.decode(results[0], (uint256)), SIG_VALIDATION_SUCCESS_UINT);
        assertTrue(successes[1]);
        assertFalse(successes[2]);
        assertEq(bytes4(results[2]), TimelockPolicy.MissingProposalCommitment.selector);
    }

    function test_commitmentCanOnlyBeConsumedByTheSameUserOperation() public {
        bytes memory proposed = hex"aabbccdd";
        PackedUserOperation memory creation = _creationOp(proposed, 3, _paymasterData());
        AtomicCallHarness.Call[] memory calls = new AtomicCallHarness.Call[](3);
        calls[0] = AtomicCallHarness.Call({
            target: address(policy), data: abi.encodeCall(policy.checkUserOpPolicy, (POLICY_ID, creation))
        });
        calls[1] = AtomicCallHarness.Call({
            target: address(entryPoint),
            data: abi.encodeCall(entryPoint.setCurrentUserOpHash, (keccak256("different user operation")))
        });
        calls[2] = AtomicCallHarness.Call({
            target: address(policy), data: abi.encodeCall(policy.createProposal, (POLICY_ID, proposed, 3))
        });
        (bool[] memory successes, bytes[] memory results) = AtomicCallHarness(WALLET).execute(calls);
        assertTrue(successes[0]);
        assertEq(abi.decode(results[0], (uint256)), SIG_VALIDATION_SUCCESS_UINT);
        assertTrue(successes[1]);
        assertFalse(successes[2]);
        assertEq(bytes4(results[2]), TimelockPolicy.MissingProposalCommitment.selector);
    }

    function test_policySignatureSliceCannotChangeCommittedProposal() public {
        bytes memory proposed = hex"aabbccdd";
        PackedUserOperation memory creation = _creationOp(proposed, 9, _paymasterData());
        creation.signature = "attacker-controlled-policy-bytes";
        AtomicCallHarness.Call[] memory calls = new AtomicCallHarness.Call[](3);
        calls[0] = AtomicCallHarness.Call({
            target: address(policy), data: abi.encodeCall(policy.checkUserOpPolicy, (POLICY_ID, creation))
        });
        calls[1] = AtomicCallHarness.Call({
            target: address(entryPoint), data: abi.encodeCall(entryPoint.setCurrentUserOpHash, (_userOpHash(creation)))
        });
        calls[2] = AtomicCallHarness.Call({
            target: address(policy), data: abi.encodeCall(policy.createProposal, (POLICY_ID, proposed, 9))
        });
        (bool[] memory successes, bytes[] memory results) = AtomicCallHarness(WALLET).execute(calls);
        assertTrue(successes[0]);
        assertEq(abi.decode(results[0], (uint256)), SIG_VALIDATION_SUCCESS_UINT);
        assertTrue(successes[1]);
        assertTrue(successes[2]);
        (TimelockPolicy.ProposalStatus status,,) = policy.getProposal(WALLET, proposed, 9, POLICY_ID, WALLET);
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Pending));
    }

    function test_executionReturnsStoredWindowAndConsumesProposal() public {
        bytes memory proposed = hex"abcdef01";
        _commitAndCreate(proposed, 5);
        (, uint256 validAfter, uint256 validUntil) = policy.getProposal(WALLET, proposed, 5, POLICY_ID, WALLET);
        vm.prank(WALLET);
        uint256 result = policy.checkUserOpPolicy(POLICY_ID, _executionOp(proposed, 5));
        assertEq(uint48(result >> 208), uint48(validAfter));
        assertEq(uint48(result >> 160), uint48(validUntil));
        (TimelockPolicy.ProposalStatus status,,) = policy.getProposal(WALLET, proposed, 5, POLICY_ID, WALLET);
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Executed));
    }

    function test_guardianCanCancelPendingProposal() public {
        bytes memory proposed = hex"abcdef01";
        _commitAndCreate(proposed, 5);
        vm.prank(GUARDIAN);
        policy.cancelProposal(POLICY_ID, WALLET, proposed, 5);
        vm.prank(WALLET);
        assertEq(policy.checkUserOpPolicy(POLICY_ID, _executionOp(proposed, 5)), SIG_VALIDATION_FAILED_UINT);
    }

    function test_unauthorizedCancellationReverts() public {
        _commitAndCreate(hex"abcdef01", 5);
        vm.prank(address(0xBAD));
        vm.expectRevert(TimelockPolicy.OnlyAccount.selector);
        policy.cancelProposal(POLICY_ID, WALLET, hex"abcdef01", 5);
    }

    function test_reinstallInvalidatesPendingProposal() public {
        bytes memory proposed = hex"abcdef01";
        _commitAndCreate(proposed, 5);
        vm.startPrank(WALLET);
        policy.onUninstall(abi.encodePacked(POLICY_ID));
        policy.onInstall(abi.encode(POLICY_ID, DELAY, EXPIRATION, GUARDIAN));
        uint256 result = policy.checkUserOpPolicy(POLICY_ID, _executionOp(proposed, 5));
        vm.stopPrank();
        assertEq(result, SIG_VALIDATION_FAILED_UINT);
        assertEq(policy.currentEpoch(POLICY_ID, WALLET), 2);
    }

    function test_creationForDifferentSenderFails() public {
        PackedUserOperation memory creation = _creationOp(hex"1234", 1, _paymasterData());
        creation.sender = address(0xDEAD);
        vm.prank(WALLET);
        assertEq(policy.checkUserOpPolicy(POLICY_ID, creation), SIG_VALIDATION_FAILED_UINT);
    }

    function test_signatureAndStatelessPathsReject() public {
        vm.prank(WALLET);
        vm.expectRevert(TimelockPolicy.SignatureValidationNotSupported.selector);
        policy.checkSignaturePolicy(POLICY_ID, address(0), bytes32(0), "");
        vm.expectRevert(TimelockPolicy.StatelessValidationNotSupported.selector);
        IStatelessValidator(address(policy)).validateSignatureWithData(bytes32(0), "", "");
        vm.expectRevert(TimelockPolicy.StatelessValidationNotSupported.selector);
        IStatelessValidatorWithSender(address(policy))
            .validateSignatureWithDataWithSender(address(0), bytes32(0), "", "");
    }
}
