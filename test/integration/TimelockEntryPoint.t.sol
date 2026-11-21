// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {IPaymaster} from "account-abstraction/interfaces/IPaymaster.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {MockTimelockAccount} from "../utils/MockTimelockAccount.sol";
import {TimelockPolicy} from "../../src/policies/TimelockPolicy.sol";

contract TimelockTestPaymaster is IPaymaster {
    IEntryPoint internal immutable entryPoint;

    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
    }

    function validatePaymasterUserOp(PackedUserOperation calldata, bytes32, uint256)
        external
        view
        returns (bytes memory context, uint256 validationData)
    {
        require(msg.sender == address(entryPoint));
        return ("", 0);
    }

    function postOp(PostOpMode, bytes calldata, uint256, uint256) external view {
        require(msg.sender == address(entryPoint));
    }
}

/// @notice End-to-end coverage for the authenticated Timelock proposal flow.
contract TimelockEntryPointTest is Test {
    IEntryPoint internal entryPoint;
    TimelockPolicy internal policy;
    MockTimelockAccount internal account;
    TimelockTestPaymaster internal paymaster;

    bytes32 internal constant POLICY_ID = bytes32(uint256(1));
    uint48 internal constant DELAY = 1 hours;
    uint48 internal constant EXPIRATION = 1 days;
    address internal constant GUARDIAN = address(0xBEEF);
    address payable internal constant BENEFICIARY = payable(address(0xCAFE));
    address internal constant BUNDLER = address(0xBA5ED);
    uint256 internal constant OWNER_KEY = 0xA11CE;

    function setUp() public {
        entryPoint = EntryPointLib.deploy();
        policy = new TimelockPolicy();
        account = new MockTimelockAccount(entryPoint, policy, POLICY_ID, vm.addr(OWNER_KEY));
        paymaster = new TimelockTestPaymaster(entryPoint);

        vm.deal(address(account), 100 ether);
        vm.deal(address(this), 100 ether);
        entryPoint.depositTo{value: 50 ether}(address(paymaster));

        account.installPolicy(abi.encode(POLICY_ID, DELAY, EXPIRATION, GUARDIAN, address(entryPoint)));
    }

    function _paymasterAndData() internal view returns (bytes memory) {
        return abi.encodePacked(address(paymaster), uint128(500_000), uint128(100_000));
    }

    function _creationOp(bytes memory proposedCallData, uint256 proposedNonce, uint256 entryPointNonce)
        internal
        view
        returns (PackedUserOperation memory)
    {
        return PackedUserOperation({
            sender: address(account),
            nonce: entryPointNonce,
            initCode: "",
            callData: policy.getProposalCreationCallData(POLICY_ID, proposedCallData, proposedNonce),
            accountGasLimits: bytes32(abi.encodePacked(uint128(500_000), uint128(500_000))),
            preVerificationGas: 100_000,
            gasFees: bytes32(abi.encodePacked(uint128(1 gwei), uint128(1 gwei))),
            paymasterAndData: _paymasterAndData(),
            signature: ""
        });
    }

    function _executionOp(bytes memory callData, uint256 nonce) internal view returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: address(account),
            nonce: nonce,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(500_000), uint128(500_000))),
            preVerificationGas: 100_000,
            gasFees: bytes32(abi.encodePacked(uint128(1 gwei), uint128(1 gwei))),
            paymasterAndData: "",
            signature: ""
        });
    }

    function _submit(PackedUserOperation memory op) internal {
        op = _sign(op);
        _submitSigned(op);
    }

    function _submitSigned(PackedUserOperation memory op) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.prank(BUNDLER, BUNDLER);
        entryPoint.handleOps(ops, BENEFICIARY);
    }

    function _expectRejected(PackedUserOperation memory op) internal {
        op = _sign(op);
        _expectSignedRejected(op);
    }

    function _expectSignedRejected(PackedUserOperation memory op) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.prank(BUNDLER, BUNDLER);
        vm.expectRevert();
        entryPoint.handleOps(ops, BENEFICIARY);
    }

    function _sign(PackedUserOperation memory op) internal view returns (PackedUserOperation memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_KEY, entryPoint.getUserOpHash(op));
        op.signature = abi.encodePacked(r, s, v);
        return op;
    }

    function _create(bytes memory proposedCallData) internal returns (uint256 proposedNonce) {
        uint256 entryPointNonce = entryPoint.getNonce(address(account), 0);
        proposedNonce = entryPointNonce + 1;
        _submit(_creationOp(proposedCallData, proposedNonce, entryPointNonce));
    }

    function _proposal(bytes memory callData, uint256 nonce)
        internal
        view
        returns (TimelockPolicy.ProposalStatus status, uint256 validAfter, uint256 validUntil)
    {
        return policy.getProposal(address(account), callData, nonce, POLICY_ID, address(account));
    }

    function testSponsoredCreationPersistsProposalAndAdvancesNonce() public {
        bytes memory callData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        uint256 createdAt = block.timestamp;

        uint256 proposedNonce = _create(callData);

        (TimelockPolicy.ProposalStatus status, uint256 validAfter, uint256 validUntil) =
            _proposal(callData, proposedNonce);
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Pending));
        assertEq(validAfter, createdAt + DELAY);
        assertEq(validUntil, createdAt + DELAY + EXPIRATION);
        assertEq(entryPoint.getNonce(address(account), 0), proposedNonce);
    }

    function testLocalUserOpHashMatchesEntryPointV09() public view {
        PackedUserOperation memory op = _creationOp(abi.encodeCall(MockTimelockAccount.setValue, (42)), 1, 0);
        assertEq(policy.getEntryPointUserOpHash(POLICY_ID, address(account), op), entryPoint.getUserOpHash(op));
    }

    function testFuzzLocalUserOpHashMatchesEntryPointV09WithPaymasterSignature(
        bytes calldata proposedCallData,
        uint256 proposedNonce,
        uint256 entryPointNonce,
        bytes calldata paymasterSignature,
        bytes calldata accountSignature
    ) public {
        vm.assume(proposedCallData.length <= 1024);
        vm.assume(paymasterSignature.length > 0 && paymasterSignature.length <= 128);
        vm.assume(accountSignature.length <= 128);

        PackedUserOperation memory op = _creationOp(proposedCallData, proposedNonce, entryPointNonce);
        op.paymasterAndData = abi.encodePacked(
            op.paymasterAndData, paymasterSignature, uint16(paymasterSignature.length), bytes8(0x22e325a297439656)
        );
        op.signature = accountSignature;

        assertEq(policy.getEntryPointUserOpHash(POLICY_ID, address(account), op), entryPoint.getUserOpHash(op));
    }

    function testUnsignedCreationIsRejected() public {
        bytes memory callData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        PackedUserOperation memory op = _creationOp(callData, 1, 0);

        _expectSignedRejected(op);

        (TimelockPolicy.ProposalStatus status,,) = _proposal(callData, 1);
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.None));
    }

    function testSignedProposalCannotBeChangedAfterSigning() public {
        bytes memory signedCallData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        PackedUserOperation memory op = _sign(_creationOp(signedCallData, 1, 0));

        bytes memory changedCallData = abi.encodeCall(MockTimelockAccount.setValue, (99));
        op.callData = policy.getProposalCreationCallData(POLICY_ID, changedCallData, 1);
        _expectSignedRejected(op);

        (TimelockPolicy.ProposalStatus status,,) = _proposal(changedCallData, 1);
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.None));
    }

    function testFullLifecycleExecutesOnlyAfterDelay() public {
        bytes memory callData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        uint256 proposedNonce = _create(callData);

        vm.warp(block.timestamp + DELAY + 1);
        _submit(_executionOp(callData, proposedNonce));

        assertEq(account.value(), 42);
        (TimelockPolicy.ProposalStatus status,,) = _proposal(callData, proposedNonce);
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Executed));
    }

    function testCreationMustUseRealPaymaster() public {
        bytes memory callData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        PackedUserOperation memory op = _creationOp(callData, 1, 0);
        op.paymasterAndData = "";

        _expectRejected(op);
        (TimelockPolicy.ProposalStatus status,,) = _proposal(callData, 1);
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.None));
    }

    function testPaymasterPaysForCreation() public {
        bytes memory callData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        uint256 accountBalance = address(account).balance;
        uint256 paymasterDeposit = entryPoint.balanceOf(address(paymaster));

        _create(callData);

        assertEq(address(account).balance, accountBalance);
        assertLt(entryPoint.balanceOf(address(paymaster)), paymasterDeposit);
    }

    function testExecutionBeforeDelayIsRejectedWithoutConsumingProposal() public {
        bytes memory callData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        uint256 proposedNonce = _create(callData);

        vm.warp(block.timestamp + DELAY);
        _expectRejected(_executionOp(callData, proposedNonce));

        assertEq(account.value(), 0);
        (TimelockPolicy.ProposalStatus status,,) = _proposal(callData, proposedNonce);
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Pending));
    }

    function testExecutionAfterExpirationIsRejectedWithoutConsumingProposal() public {
        bytes memory callData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        uint256 proposedNonce = _create(callData);

        vm.warp(block.timestamp + DELAY + EXPIRATION + 1);
        _expectRejected(_executionOp(callData, proposedNonce));

        (TimelockPolicy.ProposalStatus status,,) = _proposal(callData, proposedNonce);
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Pending));
    }

    function testExecutionWithoutProposalIsRejected() public {
        bytes memory callData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        _expectRejected(_executionOp(callData, 0));
        assertEq(account.value(), 0);
    }

    function testProposalCannotAuthorizeDifferentCalldata() public {
        bytes memory authorized = abi.encodeCall(MockTimelockAccount.setValue, (42));
        bytes memory tampered = abi.encodeCall(MockTimelockAccount.setValue, (99));
        uint256 proposedNonce = _create(authorized);

        vm.warp(block.timestamp + DELAY + 1);
        _expectRejected(_executionOp(tampered, proposedNonce));

        assertEq(account.value(), 0);
        (TimelockPolicy.ProposalStatus status,,) = _proposal(authorized, proposedNonce);
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Pending));
    }

    function testProposalCannotAuthorizeDifferentNonce() public {
        bytes memory callData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        uint256 proposedNonce = _create(callData);

        vm.warp(block.timestamp + DELAY + 1);
        _expectRejected(_executionOp(callData, proposedNonce + 1));

        assertEq(account.value(), 0);
    }

    function testGuardianCancellationPreventsExecution() public {
        bytes memory callData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        uint256 proposedNonce = _create(callData);

        vm.prank(GUARDIAN);
        policy.cancelProposal(POLICY_ID, address(account), callData, proposedNonce);

        vm.warp(block.timestamp + DELAY + 1);
        _expectRejected(_executionOp(callData, proposedNonce));
        (TimelockPolicy.ProposalStatus status,,) = _proposal(callData, proposedNonce);
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Cancelled));
    }

    function testDuplicateCreationIsRejected() public {
        bytes memory callData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        uint256 proposedNonce = _create(callData);
        uint256 nextEntryPointNonce = entryPoint.getNonce(address(account), 0);

        _expectRejected(_creationOp(callData, proposedNonce, nextEntryPointNonce));
    }

    function testReinstallInvalidatesOldProposal() public {
        bytes memory callData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        uint256 proposedNonce = _create(callData);

        account.uninstallPolicy(abi.encode(POLICY_ID));
        account.installPolicy(abi.encode(POLICY_ID, DELAY, EXPIRATION, GUARDIAN, address(entryPoint)));

        vm.warp(block.timestamp + DELAY + 1);
        _expectRejected(_executionOp(callData, proposedNonce));
        assertEq(account.value(), 0);
    }

    function testRejectedOperationDoesNotAdvanceEntryPointNonce() public {
        bytes memory callData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        _expectRejected(_executionOp(callData, 0));
        assertEq(entryPoint.getNonce(address(account), 0), 0);
    }
}
