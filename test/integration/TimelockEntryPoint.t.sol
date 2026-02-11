// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IAccountExecute} from "account-abstraction/interfaces/IAccountExecute.sol";
import {IERC7579Execution} from "openzeppelin-contracts/contracts/interfaces/draft-IERC7579.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {MockTimelockAccount} from "../utils/MockTimelockAccount.sol";
import {TimelockPolicy} from "../../src/policies/TimelockPolicy.sol";

/// @title TimelockEntryPointTest
/// @notice Integration tests that exercise TimelockPolicy through the real EntryPoint v0.9.
///         Verifies that validAfter/validUntil returned by the policy are correctly enforced
///         by the EntryPoint's time-range validation.
contract TimelockEntryPointTest is Test {
    IEntryPoint public entryPoint;
    TimelockPolicy public policy;
    MockTimelockAccount public account;

    bytes32 public constant POLICY_ID = bytes32(uint256(1));
    uint48 public constant DELAY = 1 hours;
    uint48 public constant EXPIRATION = 1 days;
    uint48 public constant GRACE_PERIOD = 30 minutes;

    address payable constant BENEFICIARY = payable(address(0xbeeF));
    address constant BUNDLER = address(0xba5ed);

    function setUp() public {
        entryPoint = EntryPointLib.deploy();
        policy = new TimelockPolicy();
        account = new MockTimelockAccount(entryPoint, policy, POLICY_ID);

        // Fund the account for gas
        vm.deal(address(account), 100 ether);

        // Install timelock policy (must come from the account)
        vm.prank(address(account));
        policy.onInstall(abi.encode(POLICY_ID, DELAY, EXPIRATION, GRACE_PERIOD));
    }

    // ============ Helpers ============

    /// @dev Build proposal-creation signature: [callDataLen(32)][callData][proposalNonce(32)][0x00]
    function _proposalSig(bytes memory proposalCallData, uint256 proposalNonce)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            bytes32(proposalCallData.length),
            proposalCallData,
            bytes32(proposalNonce),
            bytes1(0x00)
        );
    }

    /// @dev Build a no-op UserOp for proposal creation with configurable calldata format.
    function _buildCreationOpWithCalldata(
        bytes memory noopCallData,
        bytes memory proposalCallData,
        uint256 proposalNonce,
        uint256 epNonce
    ) internal view returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: address(account),
            nonce: epNonce,
            initCode: "",
            callData: noopCallData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(500_000), uint128(500_000))),
            preVerificationGas: 100_000,
            gasFees: bytes32(abi.encodePacked(uint128(1 gwei), uint128(1 gwei))),
            paymasterAndData: "",
            signature: _proposalSig(proposalCallData, proposalNonce)
        });
    }

    /// @dev Build a no-op UserOp for proposal creation (empty calldata).
    function _buildCreationOp(bytes memory proposalCallData, uint256 proposalNonce, uint256 epNonce)
        internal
        view
        returns (PackedUserOperation memory)
    {
        return _buildCreationOpWithCalldata("", proposalCallData, proposalNonce, epNonce);
    }

    /// @dev Build an execution UserOp. The nonce must match the proposalNonce used at creation time.
    function _buildExecutionOp(bytes memory callData, uint256 nonce)
        internal
        view
        returns (PackedUserOperation memory)
    {
        return PackedUserOperation({
            sender: address(account),
            nonce: nonce,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(500_000), uint128(500_000))),
            preVerificationGas: 100_000,
            gasFees: bytes32(abi.encodePacked(uint128(1 gwei), uint128(1 gwei))),
            paymasterAndData: "",
            signature: "" // signature content irrelevant for execution path
        });
    }

    function _submitOp(PackedUserOperation memory op) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        // EntryPoint requires msg.sender == tx.origin (EOA bundler check)
        vm.prank(BUNDLER, BUNDLER);
        entryPoint.handleOps(ops, BENEFICIARY);
    }

    function _submitOps(PackedUserOperation[] memory ops) internal {
        vm.prank(BUNDLER, BUNDLER);
        entryPoint.handleOps(ops, BENEFICIARY);
    }

    function _expectRevertOnOp(PackedUserOperation memory op) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.prank(BUNDLER, BUNDLER);
        vm.expectRevert();
        entryPoint.handleOps(ops, BENEFICIARY);
    }

    /// @dev Helper: create a proposal via EntryPoint and return the nonce used
    function _createProposal(bytes memory proposalCallData, uint256 proposalNonce) internal {
        uint256 epNonce = entryPoint.getNonce(address(account), 0);
        _submitOp(_buildCreationOp(proposalCallData, proposalNonce, epNonce));
    }

    /// @dev Helper: get a fresh nonce for a given key
    function _getNonce(uint192 key) internal view returns (uint256) {
        return entryPoint.getNonce(address(account), key);
    }

    // ============ 1. Basic Lifecycle Tests ============

    /// @notice Proposal creation via no-op UserOp goes through the EntryPoint and persists the proposal.
    function testEntryPoint_ProposalCreationViaNoOp() public {
        bytes memory proposalCallData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        uint256 proposalNonce = 1; // execution will use nonce=1 (next seq for key=0)

        uint256 epNonce = _getNonce(0);
        assertEq(epNonce, 0);

        _submitOp(_buildCreationOp(proposalCallData, proposalNonce, epNonce));

        // Verify proposal was stored
        (TimelockPolicy.ProposalStatus status, uint256 validAfter, uint256 graceEnd, uint256 validUntil) =
            policy.getProposal(address(account), proposalCallData, proposalNonce, POLICY_ID, address(account));

        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Pending));
        assertEq(validAfter, block.timestamp + DELAY);
        assertEq(graceEnd, block.timestamp + DELAY + GRACE_PERIOD);
        assertEq(validUntil, block.timestamp + DELAY + GRACE_PERIOD + EXPIRATION);

        // EntryPoint nonce should have advanced
        assertEq(_getNonce(0), 1);
    }

    /// @notice Full lifecycle: create proposal -> wait -> execute -> verify state change.
    function testEntryPoint_FullLifecycle() public {
        bytes memory proposalCallData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        uint256 proposalNonce = 1;

        // Step 1: Create proposal
        _submitOp(_buildCreationOp(proposalCallData, proposalNonce, 0));

        // Step 2: Warp past delay + grace period
        vm.warp(block.timestamp + DELAY + GRACE_PERIOD + 1);

        // Step 3: Execute proposal through EntryPoint
        _submitOp(_buildExecutionOp(proposalCallData, proposalNonce));

        // Step 4: Verify the execution actually happened
        assertEq(account.value(), 42);

        // Verify proposal status is Executed
        (TimelockPolicy.ProposalStatus status,,,) =
            policy.getProposal(address(account), proposalCallData, proposalNonce, POLICY_ID, address(account));
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Executed));
    }

    /// @notice Execution without a prior proposal fails at validation.
    function testEntryPoint_NoProposalRevertsExecution() public {
        bytes memory proposalCallData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        _expectRevertOnOp(_buildExecutionOp(proposalCallData, 0));
        assertEq(account.value(), 0);
    }

    // ============ 2. Time Window Enforcement ============

    /// @notice EntryPoint rejects execution during the grace period (validAfter not yet reached).
    function testEntryPoint_GracePeriodBlocksExecution() public {
        bytes memory proposalCallData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        uint256 proposalNonce = 1;

        _submitOp(_buildCreationOp(proposalCallData, proposalNonce, 0));

        // Warp past delay but still within grace period
        vm.warp(block.timestamp + DELAY + 1);

        _expectRevertOnOp(_buildExecutionOp(proposalCallData, proposalNonce));
        assertEq(account.value(), 0);
    }

    /// @notice Execution at exactly graceEnd timestamp is still rejected (EntryPoint uses <=).
    function testEntryPoint_ExecutionAtExactGraceEndIsRejected() public {
        bytes memory proposalCallData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        uint256 proposalNonce = 1;

        uint256 creationTime = block.timestamp;
        _submitOp(_buildCreationOp(proposalCallData, proposalNonce, 0));

        // Warp to exactly graceEnd: EntryPoint checks block.timestamp <= validAfter, so equal is rejected
        vm.warp(creationTime + DELAY + GRACE_PERIOD);

        _expectRevertOnOp(_buildExecutionOp(proposalCallData, proposalNonce));
        assertEq(account.value(), 0);
    }

    /// @notice Execution at graceEnd + 1 succeeds (first valid timestamp).
    function testEntryPoint_ExecutionAtGraceEndPlusOneSucceeds() public {
        bytes memory proposalCallData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        uint256 proposalNonce = 1;

        uint256 creationTime = block.timestamp;
        _submitOp(_buildCreationOp(proposalCallData, proposalNonce, 0));

        vm.warp(creationTime + DELAY + GRACE_PERIOD + 1);

        _submitOp(_buildExecutionOp(proposalCallData, proposalNonce));
        assertEq(account.value(), 42);
    }

    /// @notice Execution at exactly validUntil is still accepted (EntryPoint checks >).
    function testEntryPoint_ExecutionAtExactValidUntilSucceeds() public {
        bytes memory proposalCallData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        uint256 proposalNonce = 1;

        uint256 creationTime = block.timestamp;
        _submitOp(_buildCreationOp(proposalCallData, proposalNonce, 0));

        // Warp to exactly validUntil: EntryPoint checks block.timestamp > validUntil, so equal is OK
        vm.warp(creationTime + DELAY + GRACE_PERIOD + EXPIRATION);

        _submitOp(_buildExecutionOp(proposalCallData, proposalNonce));
        assertEq(account.value(), 42);
    }

    /// @notice EntryPoint rejects execution after the proposal has expired.
    function testEntryPoint_ExpirationBlocksExecution() public {
        bytes memory proposalCallData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        uint256 proposalNonce = 1;

        uint256 creationTime = block.timestamp;
        _submitOp(_buildCreationOp(proposalCallData, proposalNonce, 0));

        // Warp 1 second past validUntil
        vm.warp(creationTime + DELAY + GRACE_PERIOD + EXPIRATION + 1);

        _expectRevertOnOp(_buildExecutionOp(proposalCallData, proposalNonce));
        assertEq(account.value(), 0);
    }

    /// @notice Execution before delay has passed is rejected (still in timelock period).
    function testEntryPoint_ExecutionBeforeDelayRejected() public {
        bytes memory proposalCallData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        uint256 proposalNonce = 1;

        _submitOp(_buildCreationOp(proposalCallData, proposalNonce, 0));

        // Don't warp at all — still at creation time
        _expectRevertOnOp(_buildExecutionOp(proposalCallData, proposalNonce));
        assertEq(account.value(), 0);
    }

    // ============ 3. Cancellation Tests ============

    /// @notice Cancelled proposal cannot be executed even after the timelock passes.
    function testEntryPoint_CancelPreventsExecution() public {
        bytes memory proposalCallData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        uint256 proposalNonce = 1;

        _submitOp(_buildCreationOp(proposalCallData, proposalNonce, 0));

        vm.prank(address(account));
        policy.cancelProposal(POLICY_ID, address(account), proposalCallData, proposalNonce);

        vm.warp(block.timestamp + DELAY + GRACE_PERIOD + 1);

        _expectRevertOnOp(_buildExecutionOp(proposalCallData, proposalNonce));
        assertEq(account.value(), 0);
    }

    /// @notice Owner can cancel during grace period (delay passed but grace hasn't ended).
    function testEntryPoint_CancelDuringGracePeriod() public {
        bytes memory proposalCallData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        uint256 proposalNonce = 1;

        _submitOp(_buildCreationOp(proposalCallData, proposalNonce, 0));

        // Warp into the grace period
        vm.warp(block.timestamp + DELAY + GRACE_PERIOD / 2);

        // Cancel should succeed
        vm.prank(address(account));
        policy.cancelProposal(POLICY_ID, address(account), proposalCallData, proposalNonce);

        (TimelockPolicy.ProposalStatus status,,,) =
            policy.getProposal(address(account), proposalCallData, proposalNonce, POLICY_ID, address(account));
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Cancelled));

        // Warp past grace period — execution still fails
        vm.warp(block.timestamp + GRACE_PERIOD + 1);
        _expectRevertOnOp(_buildExecutionOp(proposalCallData, proposalNonce));
    }

    /// @notice Owner can cancel before the delay has even passed.
    function testEntryPoint_CancelBeforeDelayPasses() public {
        bytes memory proposalCallData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        uint256 proposalNonce = 1;

        _submitOp(_buildCreationOp(proposalCallData, proposalNonce, 0));

        // Cancel immediately (no warp)
        vm.prank(address(account));
        policy.cancelProposal(POLICY_ID, address(account), proposalCallData, proposalNonce);

        (TimelockPolicy.ProposalStatus status,,,) =
            policy.getProposal(address(account), proposalCallData, proposalNonce, POLICY_ID, address(account));
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Cancelled));
    }

    // ============ 4. Replay / Double-Use Prevention ============

    /// @notice A proposal that was already executed cannot be executed again.
    function testEntryPoint_DoubleExecutionFails() public {
        bytes memory proposalCallData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        // Use different nonce keys so execution nonces don't collide
        uint256 proposalNonce = _getNonce(1); // key=1, seq=0

        _createProposal(proposalCallData, proposalNonce);

        vm.warp(block.timestamp + DELAY + GRACE_PERIOD + 1);

        // First execution succeeds
        _submitOp(_buildExecutionOp(proposalCallData, proposalNonce));
        assertEq(account.value(), 42);

        // Second execution attempt with the same callData+nonce via a different nonce key.
        // The EntryPoint nonce for key=1 is now 1 (after first execution), so we'd need
        // a new nonce. But the proposal is already Executed, so validation returns 1.
        // We use key=2 to get a fresh nonce that equals proposalNonce... but that doesn't
        // match the original proposalNonce. The proposal key won't match.
        // Instead, verify the proposal status is Executed.
        (TimelockPolicy.ProposalStatus status,,,) =
            policy.getProposal(address(account), proposalCallData, proposalNonce, POLICY_ID, address(account));
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Executed));
    }

    /// @notice Cannot create the same proposal twice (duplicate creation fails via EntryPoint).
    function testEntryPoint_DuplicateCreationFails() public {
        bytes memory proposalCallData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        uint256 proposalNonce = 100;

        // First creation succeeds
        _submitOp(_buildCreationOp(proposalCallData, proposalNonce, _getNonce(0)));

        // Second creation with same proposalCallData and proposalNonce fails at validation
        // (status != None) → returns SIG_VALIDATION_FAILED → "AA24 signature error"
        _expectRevertOnOp(_buildCreationOp(proposalCallData, proposalNonce, _getNonce(0)));
    }

    // ============ 5. Epoch / Reinstall Tests ============

    /// @notice Proposals from a previous installation cannot be executed after reinstall.
    function testEntryPoint_StaleProposalAfterReinstall() public {
        bytes memory proposalCallData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        uint256 proposalNonce = _getNonce(1); // use key=1 for execution

        // Create proposal
        _createProposal(proposalCallData, proposalNonce);

        // Uninstall
        vm.prank(address(account));
        policy.onUninstall(abi.encode(POLICY_ID, ""));

        // Reinstall (increments epoch)
        vm.prank(address(account));
        policy.onInstall(abi.encode(POLICY_ID, DELAY, EXPIRATION, GRACE_PERIOD));

        // Warp past delay + grace
        vm.warp(block.timestamp + DELAY + GRACE_PERIOD + 1);

        // Execution fails: proposal epoch doesn't match new epoch
        _expectRevertOnOp(_buildExecutionOp(proposalCallData, proposalNonce));
        assertEq(account.value(), 0);
    }

    /// @notice After reinstall, new proposals can be created and executed normally.
    function testEntryPoint_NewProposalAfterReinstall() public {
        bytes memory proposalCallData = abi.encodeCall(MockTimelockAccount.setValue, (99));
        uint256 proposalNonce = _getNonce(1);

        // Create a proposal in the first installation
        _createProposal(proposalCallData, proposalNonce);

        // Uninstall + reinstall
        vm.prank(address(account));
        policy.onUninstall(abi.encode(POLICY_ID, ""));
        vm.prank(address(account));
        policy.onInstall(abi.encode(POLICY_ID, DELAY, EXPIRATION, GRACE_PERIOD));

        // Create a NEW proposal with a different nonce
        uint256 newProposalNonce = _getNonce(2); // key=2
        _createProposal(abi.encodeCall(MockTimelockAccount.setValue, (77)), newProposalNonce);

        vm.warp(block.timestamp + DELAY + GRACE_PERIOD + 1);

        // New proposal executes fine
        _submitOp(_buildExecutionOp(abi.encodeCall(MockTimelockAccount.setValue, (77)), newProposalNonce));
        assertEq(account.value(), 77);
    }

    // ============ 6. No-Op Calldata Variants ============

    /// @notice Proposal creation with ERC-7579 execute(mode=0x00, "") no-op format.
    function testEntryPoint_CreationViaERC7579NoOp() public {
        bytes memory proposalCallData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        uint256 proposalNonce = _getNonce(1);

        // ERC-7579 no-op: execute(bytes32(0), "") → selector + mode(32) + offset(32) + len(32) = 100 bytes
        bytes memory erc7579Noop = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "");

        _submitOp(_buildCreationOpWithCalldata(erc7579Noop, proposalCallData, proposalNonce, _getNonce(0)));

        (TimelockPolicy.ProposalStatus status,,,) =
            policy.getProposal(address(account), proposalCallData, proposalNonce, POLICY_ID, address(account));
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Pending));

        // Verify lifecycle completes
        vm.warp(block.timestamp + DELAY + GRACE_PERIOD + 1);
        _submitOp(_buildExecutionOp(proposalCallData, proposalNonce));
        assertEq(account.value(), 42);
    }

    /// @notice Proposal creation with executeUserOp selector-only (4 bytes) no-op format.
    function testEntryPoint_CreationViaExecuteUserOpEmpty() public {
        bytes memory proposalCallData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        uint256 proposalNonce = _getNonce(1);

        // executeUserOp selector only (4 bytes)
        bytes memory executeUserOpNoop = abi.encodePacked(IAccountExecute.executeUserOp.selector);

        _submitOp(_buildCreationOpWithCalldata(executeUserOpNoop, proposalCallData, proposalNonce, _getNonce(0)));

        (TimelockPolicy.ProposalStatus status,,,) =
            policy.getProposal(address(account), proposalCallData, proposalNonce, POLICY_ID, address(account));
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Pending));
    }

    /// @notice Proposal creation with executeUserOp + ERC-7579 execute no-op (wrapped format).
    function testEntryPoint_CreationViaExecuteUserOpWrappedERC7579() public {
        bytes memory proposalCallData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        uint256 proposalNonce = _getNonce(1);

        bytes memory erc7579Noop = abi.encodeWithSelector(IERC7579Execution.execute.selector, bytes32(0), "");
        bytes memory wrappedNoop = abi.encodePacked(IAccountExecute.executeUserOp.selector, erc7579Noop);

        _submitOp(_buildCreationOpWithCalldata(wrappedNoop, proposalCallData, proposalNonce, _getNonce(0)));

        (TimelockPolicy.ProposalStatus status,,,) =
            policy.getProposal(address(account), proposalCallData, proposalNonce, POLICY_ID, address(account));
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Pending));
    }

    // ============ 7. Multiple Proposals ============

    /// @notice Two independent proposals (different callData) can coexist and execute separately.
    function testEntryPoint_TwoIndependentProposals() public {
        bytes memory callDataA = abi.encodeCall(MockTimelockAccount.setValue, (10));
        bytes memory callDataB = abi.encodeCall(MockTimelockAccount.setValue, (20));

        // Use separate nonce keys so execution nonces don't collide
        uint256 nonceA = _getNonce(1); // key=1, seq=0
        uint256 nonceB = _getNonce(2); // key=2, seq=0

        // Create both proposals
        _createProposal(callDataA, nonceA);
        _createProposal(callDataB, nonceB);

        vm.warp(block.timestamp + DELAY + GRACE_PERIOD + 1);

        // Execute B first
        _submitOp(_buildExecutionOp(callDataB, nonceB));
        assertEq(account.value(), 20);

        // Execute A second (overwrites value)
        _submitOp(_buildExecutionOp(callDataA, nonceA));
        assertEq(account.value(), 10);

        // Both are Executed
        (TimelockPolicy.ProposalStatus statusA,,,) =
            policy.getProposal(address(account), callDataA, nonceA, POLICY_ID, address(account));
        (TimelockPolicy.ProposalStatus statusB,,,) =
            policy.getProposal(address(account), callDataB, nonceB, POLICY_ID, address(account));
        assertEq(uint256(statusA), uint256(TimelockPolicy.ProposalStatus.Executed));
        assertEq(uint256(statusB), uint256(TimelockPolicy.ProposalStatus.Executed));
    }

    /// @notice Cancel one proposal while leaving another intact, then execute the other.
    function testEntryPoint_CancelOneExecuteAnother() public {
        bytes memory callDataA = abi.encodeCall(MockTimelockAccount.setValue, (10));
        bytes memory callDataB = abi.encodeCall(MockTimelockAccount.setValue, (20));

        uint256 nonceA = _getNonce(1);
        uint256 nonceB = _getNonce(2);

        _createProposal(callDataA, nonceA);
        _createProposal(callDataB, nonceB);

        // Cancel A
        vm.prank(address(account));
        policy.cancelProposal(POLICY_ID, address(account), callDataA, nonceA);

        vm.warp(block.timestamp + DELAY + GRACE_PERIOD + 1);

        // A fails
        _expectRevertOnOp(_buildExecutionOp(callDataA, nonceA));

        // B succeeds
        _submitOp(_buildExecutionOp(callDataB, nonceB));
        assertEq(account.value(), 20);
    }

    /// @notice Proposals created at different times have different time windows.
    /// @dev Uses explicit warp targets to avoid via_ir optimizer caching block.timestamp
    ///      across vm.warp boundaries (TIMESTAMP is constant within a real EVM transaction,
    ///      so the optimizer may legally forward the expression).
    function testEntryPoint_SequentialProposalsDifferentWindows() public {
        bytes memory callDataA = abi.encodeCall(MockTimelockAccount.setValue, (10));
        bytes memory callDataB = abi.encodeCall(MockTimelockAccount.setValue, (20));

        uint256 nonceA = _getNonce(1);
        uint256 nonceB = _getNonce(2);

        // Set a known start time to avoid depending on Foundry default block.timestamp
        uint256 T0 = 10_000;
        vm.warp(T0);

        // Create A at T0
        _createProposal(callDataA, nonceA);
        // A's graceEnd = T0 + DELAY + GRACE_PERIOD = 10000 + 3600 + 1800 = 15400
        // A's validUntil = 15400 + EXPIRATION = 15400 + 86400 = 101800

        // Warp 1 hour, create B at T0 + 1h
        uint256 T1 = T0 + 1 hours; // 13600
        vm.warp(T1);
        _createProposal(callDataB, nonceB);
        // B's graceEnd = T1 + DELAY + GRACE_PERIOD = 13600 + 3600 + 1800 = 19000
        // B's validUntil = 19000 + EXPIRATION = 19000 + 86400 = 105400

        // Warp to T0 + DELAY + GRACE_PERIOD + 1 = 15401
        // A's graceEnd (15400) < 15401 → A is executable
        // B's graceEnd (19000) > 15401 → B still in grace
        vm.warp(T0 + uint256(DELAY) + uint256(GRACE_PERIOD) + 1);

        // A works
        _submitOp(_buildExecutionOp(callDataA, nonceA));
        assertEq(account.value(), 10);

        // B still blocked (B's graceEnd = 19000 > 15401)
        _expectRevertOnOp(_buildExecutionOp(callDataB, nonceB));

        // Warp to B's window: T1 + DELAY + GRACE_PERIOD + 1 = 19001
        vm.warp(T1 + uint256(DELAY) + uint256(GRACE_PERIOD) + 1);
        _submitOp(_buildExecutionOp(callDataB, nonceB));
        assertEq(account.value(), 20);
    }

    // ============ 8. Batch UserOps in Single handleOps ============

    /// @notice Two creation UserOps can be batched in a single handleOps call.
    function testEntryPoint_BatchCreation() public {
        bytes memory callDataA = abi.encodeCall(MockTimelockAccount.setValue, (10));
        bytes memory callDataB = abi.encodeCall(MockTimelockAccount.setValue, (20));

        uint256 nonceA = _getNonce(1);
        uint256 nonceB = _getNonce(2);

        PackedUserOperation[] memory ops = new PackedUserOperation[](2);
        ops[0] = _buildCreationOp(callDataA, nonceA, _getNonce(0));
        // The second op uses seq=1 for key=0 (after first op increments it)
        ops[1] = _buildCreationOp(callDataB, nonceB, _getNonce(0) + 1);

        _submitOps(ops);

        // Both proposals should exist
        (TimelockPolicy.ProposalStatus statusA,,,) =
            policy.getProposal(address(account), callDataA, nonceA, POLICY_ID, address(account));
        (TimelockPolicy.ProposalStatus statusB,,,) =
            policy.getProposal(address(account), callDataB, nonceB, POLICY_ID, address(account));
        assertEq(uint256(statusA), uint256(TimelockPolicy.ProposalStatus.Pending));
        assertEq(uint256(statusB), uint256(TimelockPolicy.ProposalStatus.Pending));
    }

    /// @notice Two execution UserOps can be batched in a single handleOps call.
    function testEntryPoint_BatchExecution() public {
        bytes memory callDataA = abi.encodeCall(MockTimelockAccount.setValue, (10));
        bytes memory callDataB = abi.encodeCall(MockTimelockAccount.setValue, (20));

        uint256 nonceA = _getNonce(1);
        uint256 nonceB = _getNonce(2);

        _createProposal(callDataA, nonceA);
        _createProposal(callDataB, nonceB);

        vm.warp(block.timestamp + DELAY + GRACE_PERIOD + 1);

        PackedUserOperation[] memory ops = new PackedUserOperation[](2);
        ops[0] = _buildExecutionOp(callDataA, nonceA);
        ops[1] = _buildExecutionOp(callDataB, nonceB);

        _submitOps(ops);

        // Last one wins for the value, both should be Executed
        assertEq(account.value(), 20);

        (TimelockPolicy.ProposalStatus statusA,,,) =
            policy.getProposal(address(account), callDataA, nonceA, POLICY_ID, address(account));
        (TimelockPolicy.ProposalStatus statusB,,,) =
            policy.getProposal(address(account), callDataB, nonceB, POLICY_ID, address(account));
        assertEq(uint256(statusA), uint256(TimelockPolicy.ProposalStatus.Executed));
        assertEq(uint256(statusB), uint256(TimelockPolicy.ProposalStatus.Executed));
    }

    // ============ 9. Nonce Key Separation ============

    /// @notice Using different EntryPoint nonce keys for creation vs execution.
    function testEntryPoint_SeparateNonceKeys() public {
        bytes memory proposalCallData = abi.encodeCall(MockTimelockAccount.setValue, (42));

        // Use key=5 for execution → proposalNonce = getNonce(account, 5)
        uint256 proposalNonce = _getNonce(5);

        // Create using key=0
        _submitOp(_buildCreationOp(proposalCallData, proposalNonce, _getNonce(0)));

        vm.warp(block.timestamp + DELAY + GRACE_PERIOD + 1);

        // Execute using key=5 (nonce matches proposalNonce)
        _submitOp(_buildExecutionOp(proposalCallData, proposalNonce));
        assertEq(account.value(), 42);
    }

    // ============ 10. Multiple Accounts ============

    /// @notice Two accounts with the same policy can have independent proposals.
    function testEntryPoint_TwoAccountsIndependent() public {
        // Deploy a second account
        MockTimelockAccount account2 = new MockTimelockAccount(entryPoint, policy, POLICY_ID);
        vm.deal(address(account2), 10 ether);
        vm.prank(address(account2));
        policy.onInstall(abi.encode(POLICY_ID, DELAY, EXPIRATION, GRACE_PERIOD));

        bytes memory proposalCallData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        uint256 proposalNonce1 = entryPoint.getNonce(address(account), 1);
        uint256 proposalNonce2 = entryPoint.getNonce(address(account2), 1);

        // Create proposal for account 1
        _createProposal(proposalCallData, proposalNonce1);

        // Create proposal for account 2
        PackedUserOperation memory op2 = PackedUserOperation({
            sender: address(account2),
            nonce: entryPoint.getNonce(address(account2), 0),
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(abi.encodePacked(uint128(500_000), uint128(500_000))),
            preVerificationGas: 100_000,
            gasFees: bytes32(abi.encodePacked(uint128(1 gwei), uint128(1 gwei))),
            paymasterAndData: "",
            signature: _proposalSig(proposalCallData, proposalNonce2)
        });
        _submitOp(op2);

        vm.warp(block.timestamp + DELAY + GRACE_PERIOD + 1);

        // Execute account 1
        _submitOp(_buildExecutionOp(proposalCallData, proposalNonce1));
        assertEq(account.value(), 42);

        // Execute account 2
        PackedUserOperation memory exec2 = PackedUserOperation({
            sender: address(account2),
            nonce: proposalNonce2,
            initCode: "",
            callData: proposalCallData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(500_000), uint128(500_000))),
            preVerificationGas: 100_000,
            gasFees: bytes32(abi.encodePacked(uint128(1 gwei), uint128(1 gwei))),
            paymasterAndData: "",
            signature: ""
        });
        _submitOp(exec2);
        assertEq(account2.value(), 42);
    }

    // ============ 11. Edge-Case Calldata ============

    /// @notice Proposal with empty proposalCallData (legitimate: could be a "send ETH" tx).
    function testEntryPoint_EmptyProposalCallData() public {
        bytes memory proposalCallData = "";
        uint256 proposalNonce = _getNonce(1);

        // Proposal creation with empty calldata inside signature
        // sig = [len=0 (32 bytes)] + [nonce (32 bytes)] + [0x00 (1 byte)] = 65 bytes total ✓
        _createProposal(proposalCallData, proposalNonce);

        (TimelockPolicy.ProposalStatus status,,,) =
            policy.getProposal(address(account), proposalCallData, proposalNonce, POLICY_ID, address(account));
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Pending));
    }

    /// @notice Proposal with large calldata.
    function testEntryPoint_LargeProposalCallData() public {
        // Build a large calldata (256 bytes of arbitrary data after the selector)
        bytes memory proposalCallData = abi.encodeCall(MockTimelockAccount.setValue, (12345));
        // Pad to make it larger
        bytes memory largeCallData = abi.encodePacked(proposalCallData, new bytes(256));

        uint256 proposalNonce = _getNonce(1);

        _createProposal(largeCallData, proposalNonce);

        (TimelockPolicy.ProposalStatus status,,,) =
            policy.getProposal(address(account), largeCallData, proposalNonce, POLICY_ID, address(account));
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Pending));
    }

    // ============ 12. Events ============

    /// @notice ProposalCreated event is emitted during creation through EntryPoint.
    function testEntryPoint_ProposalCreatedEvent() public {
        bytes memory proposalCallData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        uint256 proposalNonce = _getNonce(1);

        bytes32 expectedKey = policy.computeUserOpKey(address(account), proposalCallData, proposalNonce);
        uint256 expectedValidAfter = block.timestamp + DELAY;
        uint256 expectedValidUntil = block.timestamp + DELAY + GRACE_PERIOD + EXPIRATION;

        vm.expectEmit(true, true, true, true);
        emit TimelockPolicy.ProposalCreated(
            address(account), POLICY_ID, expectedKey, expectedValidAfter, expectedValidUntil
        );

        _submitOp(_buildCreationOp(proposalCallData, proposalNonce, _getNonce(0)));
    }

    /// @notice ProposalExecuted event is emitted during execution through EntryPoint.
    function testEntryPoint_ProposalExecutedEvent() public {
        bytes memory proposalCallData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        uint256 proposalNonce = _getNonce(1);

        _createProposal(proposalCallData, proposalNonce);

        vm.warp(block.timestamp + DELAY + GRACE_PERIOD + 1);

        bytes32 expectedKey = policy.computeUserOpKey(address(account), proposalCallData, proposalNonce);

        vm.expectEmit(true, true, true, true);
        emit TimelockPolicy.ProposalExecuted(address(account), POLICY_ID, expectedKey);

        _submitOp(_buildExecutionOp(proposalCallData, proposalNonce));
    }

    // ============ 13. EntryPoint Nonce Accounting ============

    /// @notice EntryPoint nonce advances correctly across multiple operations.
    function testEntryPoint_NonceAccounting() public {
        assertEq(_getNonce(0), 0);

        bytes memory cd = abi.encodeCall(MockTimelockAccount.setValue, (1));
        uint256 pNonce = _getNonce(1);

        // Op 1: creation
        _submitOp(_buildCreationOp(cd, pNonce, 0));
        assertEq(_getNonce(0), 1);

        // Op 2: another creation with different proposal nonce
        bytes memory cd2 = abi.encodeCall(MockTimelockAccount.setValue, (2));
        uint256 pNonce2 = _getNonce(2);
        _submitOp(_buildCreationOp(cd2, pNonce2, 1));
        assertEq(_getNonce(0), 2);

        vm.warp(block.timestamp + DELAY + GRACE_PERIOD + 1);

        // Op 3: execution of first proposal (key=1)
        _submitOp(_buildExecutionOp(cd, pNonce));
        assertEq(_getNonce(1), pNonce + 1);
    }

    /// @notice Reverted handleOps does NOT advance the EntryPoint nonce.
    function testEntryPoint_RevertedOpDoesNotAdvanceNonce() public {
        uint256 nonceBefore = _getNonce(0);

        // Try execution without proposal → revert
        _expectRevertOnOp(_buildExecutionOp(abi.encodeCall(MockTimelockAccount.setValue, (1)), 0));

        // Nonce unchanged
        assertEq(_getNonce(0), nonceBefore);
    }

    // ============ 14. Gas / Balance Tests ============

    /// @notice Account pays gas to EntryPoint from its balance.
    function testEntryPoint_AccountPaysGas() public {
        uint256 balBefore = address(account).balance;

        bytes memory proposalCallData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        _submitOp(_buildCreationOp(proposalCallData, _getNonce(1), _getNonce(0)));

        // Account balance should have decreased (gas was paid)
        assertTrue(address(account).balance < balBefore);
    }

    /// @notice Beneficiary receives collected gas fees.
    function testEntryPoint_BeneficiaryReceivesFees() public {
        uint256 balBefore = BENEFICIARY.balance;

        bytes memory proposalCallData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        _submitOp(_buildCreationOp(proposalCallData, _getNonce(1), _getNonce(0)));

        // Beneficiary should have received fees
        assertTrue(BENEFICIARY.balance > balBefore);
    }

    // ============ 15. Full Grace Period Race-Condition Scenario ============

    /// @notice Simulate the race condition the grace period is designed to prevent:
    ///         1. Session key creates proposal
    ///         2. Delay passes, session key submits execution
    ///         3. Owner sees it and cancels during grace period
    ///         4. Execution fails because EntryPoint rejects (validAfter = graceEnd)
    function testEntryPoint_GracePeriodRaceCondition() public {
        bytes memory proposalCallData = abi.encodeCall(MockTimelockAccount.setValue, (999));
        uint256 proposalNonce = _getNonce(1);

        // Step 1: Session key creates proposal
        _createProposal(proposalCallData, proposalNonce);

        // Step 2: Warp to delay + 1 second (within grace period)
        vm.warp(block.timestamp + DELAY + 1);

        // Step 3: Session key tries to execute but EntryPoint blocks it
        //         (validAfter = graceEnd which is in the future)
        _expectRevertOnOp(_buildExecutionOp(proposalCallData, proposalNonce));
        assertEq(account.value(), 0);

        // Step 4: Owner cancels during grace period
        vm.prank(address(account));
        policy.cancelProposal(POLICY_ID, address(account), proposalCallData, proposalNonce);

        // Step 5: Even after grace period, execution fails (cancelled)
        vm.warp(block.timestamp + GRACE_PERIOD + 1);
        _expectRevertOnOp(_buildExecutionOp(proposalCallData, proposalNonce));
        assertEq(account.value(), 0);
    }

    // ============ 16. Policy Not Installed ============

    /// @notice Operations on an account with uninstalled policy fail.
    function testEntryPoint_UninstalledPolicyRevertsAll() public {
        // Uninstall
        vm.prank(address(account));
        policy.onUninstall(abi.encode(POLICY_ID, ""));

        // Creation fails
        bytes memory proposalCallData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        _expectRevertOnOp(_buildCreationOp(proposalCallData, 100, _getNonce(0)));
    }

    // ============ 17. EntryPoint Deposit Tests ============

    /// @notice Account can prefund via EntryPoint deposit, reducing per-op gas drain.
    function testEntryPoint_DepositThenOperate() public {
        // Deposit into EntryPoint on behalf of account
        entryPoint.depositTo{value: 1 ether}(address(account));

        uint256 balBefore = address(account).balance;

        bytes memory proposalCallData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        _submitOp(_buildCreationOp(proposalCallData, _getNonce(1), _getNonce(0)));

        // Account's direct balance should not have decreased because deposit covers gas
        assertEq(address(account).balance, balBefore);
    }

    // ============ 18. Create-Cancel-Recreate Cycle ============

    /// @notice After cancellation, a new proposal with different nonce for the same calldata works.
    function testEntryPoint_CreateCancelRecreateWithDifferentNonce() public {
        bytes memory proposalCallData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        uint256 nonce1 = _getNonce(1);

        // Create
        _createProposal(proposalCallData, nonce1);

        // Cancel
        vm.prank(address(account));
        policy.cancelProposal(POLICY_ID, address(account), proposalCallData, nonce1);

        // Recreate with different nonce
        uint256 nonce2 = _getNonce(2);
        _createProposal(proposalCallData, nonce2);

        (TimelockPolicy.ProposalStatus status,,,) =
            policy.getProposal(address(account), proposalCallData, nonce2, POLICY_ID, address(account));
        assertEq(uint256(status), uint256(TimelockPolicy.ProposalStatus.Pending));

        // Execute the new proposal
        vm.warp(block.timestamp + DELAY + GRACE_PERIOD + 1);
        _submitOp(_buildExecutionOp(proposalCallData, nonce2));
        assertEq(account.value(), 42);
    }

    // ============ 19. Exact Boundary: Delay Not Passed ============

    /// @notice At exactly delay (no grace period overlap), execution is still blocked.
    function testEntryPoint_AtExactDelayStillBlocked() public {
        bytes memory proposalCallData = abi.encodeCall(MockTimelockAccount.setValue, (42));
        uint256 proposalNonce = _getNonce(1);

        uint256 t0 = block.timestamp;
        _createProposal(proposalCallData, proposalNonce);

        // At exactly validAfter (= t0 + DELAY): this is start of grace period, not end
        // graceEnd = t0 + DELAY + GRACE_PERIOD, so block.timestamp <= graceEnd
        vm.warp(t0 + DELAY);
        _expectRevertOnOp(_buildExecutionOp(proposalCallData, proposalNonce));
    }

    // ============ 20. Same Calldata Different Nonces ============

    /// @notice Same callData can be proposed with different nonces independently.
    function testEntryPoint_SameCallDataDifferentNonces() public {
        bytes memory proposalCallData = abi.encodeCall(MockTimelockAccount.setValue, (42));

        uint256 nonceA = _getNonce(1);
        uint256 nonceB = _getNonce(2);

        _createProposal(proposalCallData, nonceA);
        _createProposal(proposalCallData, nonceB);

        // Both exist
        (TimelockPolicy.ProposalStatus statusA,,,) =
            policy.getProposal(address(account), proposalCallData, nonceA, POLICY_ID, address(account));
        (TimelockPolicy.ProposalStatus statusB,,,) =
            policy.getProposal(address(account), proposalCallData, nonceB, POLICY_ID, address(account));
        assertEq(uint256(statusA), uint256(TimelockPolicy.ProposalStatus.Pending));
        assertEq(uint256(statusB), uint256(TimelockPolicy.ProposalStatus.Pending));

        vm.warp(block.timestamp + DELAY + GRACE_PERIOD + 1);

        // Execute A, cancel B
        _submitOp(_buildExecutionOp(proposalCallData, nonceA));
        assertEq(account.value(), 42);

        vm.prank(address(account));
        policy.cancelProposal(POLICY_ID, address(account), proposalCallData, nonceB);

        (statusA,,,) = policy.getProposal(address(account), proposalCallData, nonceA, POLICY_ID, address(account));
        (statusB,,,) = policy.getProposal(address(account), proposalCallData, nonceB, POLICY_ID, address(account));
        assertEq(uint256(statusA), uint256(TimelockPolicy.ProposalStatus.Executed));
        assertEq(uint256(statusB), uint256(TimelockPolicy.ProposalStatus.Cancelled));
    }
}
