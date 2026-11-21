// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {TimelockPolicy} from "src/policies/TimelockPolicy.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {MockTimelockEntryPoint} from "test/utils/MockTimelockEntryPoint.sol";

/// @author taek <leekt216@gmail.com>
/// @notice Halmos proof: executing a Pending, current-epoch TimelockPolicy proposal returns an
///         ERC-4337 packed validation window whose high 48 bits == the STORED proposal.validAfter,
///         next 48 bits == the STORED proposal.validUntil, and low 160 bits (authorizer) == 0 (success).
/// @dev The proposal is created through the canonical validation commitment followed by the real
///      execution-phase createProposal call, so the stored validAfter/validUntil are genuine.
///      The assertion reads the STORED fields via the public getProposal getter (not a recompute
///      of block.timestamp+delay), then compares the extracted bitfields of the returned packed
///      value against them — the packing layout is the contract's public ABI to the EntryPoint.
///      The symbolic parameters keep the execution-time uint48 bound satisfiable.
contract TimelockExecWindowHalmos is SymTest, Test {
    TimelockPolicy policy;
    MockTimelockEntryPoint entryPoint;

    // The (id, account) pair. account == address(this) is the caller of checkUserOpPolicy,
    // which becomes both userOp.sender and the storage account key.
    bytes32 constant ID = bytes32(uint256(0x7e10c0));

    function setUp() external {
        // Etch runtime code to avoid halmos-0.3.3 routing `new` through deployCode. No constructor state.
        policy = TimelockPolicy(address(0xACE));
        vm.etch(address(policy), type(TimelockPolicy).runtimeCode);
        entryPoint = MockTimelockEntryPoint(address(0xE11));
        vm.etch(address(entryPoint), type(MockTimelockEntryPoint).runtimeCode);
    }

    function _installData(uint48 delay, uint48 expirationPeriod, address guardian)
        internal
        view
        returns (bytes memory)
    {
        return abi.encodePacked(ID, abi.encode(delay, expirationPeriod, guardian, address(entryPoint)));
    }

    function _creationUserOp(bytes memory execCallData, uint256 proposalNonce)
        internal
        view
        returns (PackedUserOperation memory op)
    {
        op.sender = address(this);
        op.nonce = 0;
        op.callData = policy.getProposalCreationCallData(ID, execCallData, proposalNonce);
        op.paymasterAndData = abi.encodePacked(address(0xBEEF), uint128(1), uint128(1));
    }

    // A UserOp with real (non-no-op) callData + matching nonce => routes to EXECUTION of the
    // proposal keyed by keccak(sender, keccak(callData), nonce).
    function _executionUserOp(bytes memory execCallData, uint256 proposalNonce)
        internal
        view
        returns (PackedUserOperation memory op)
    {
        op.sender = address(this);
        op.nonce = proposalNonce;
        op.callData = execCallData;
        op.signature = "";
    }

    function _commitAndCreate(bytes memory execCallData, uint256 proposalNonce) internal {
        PackedUserOperation memory creation = _creationUserOp(execCallData, proposalNonce);
        policy.checkUserOpPolicy(ID, creation);
        entryPoint.setCurrentUserOpHash(policy.getEntryPointUserOpHash(ID, address(this), creation));
        policy.createProposal(ID, execCallData, proposalNonce);
    }

    /// @notice The exact window the EntryPoint reads: executing a live Pending/current-epoch proposal
    ///         returns _packValidationData(storedValidAfter, storedValidUntil) with success authorizer==0.
    ///         Single load-bearing assertion: the three extracted bitfields all match the stored state.
    function check_ExecReturnsStoredWindow(uint48 delay, uint48 expirationPeriod, uint256 proposalNonce) external {
        // Keep both installation and execution-time timestamp bounds satisfiable.
        vm.assume(delay > 0);
        vm.assume(expirationPeriod > 0);
        vm.assume(block.timestamp <= type(uint48).max);
        vm.assume(uint256(delay) + uint256(expirationPeriod) <= uint256(type(uint48).max) - block.timestamp);

        // A concrete, non-no-op execution calldata (a plain 4-byte selector is NOT a recognized no-op).
        bytes memory execCallData = hex"11223344";

        policy.onInstall(_installData(delay, expirationPeriod, address(0)));

        // Validation commits the signed proposal fields; execution consumes the commitment.
        _commitAndCreate(execCallData, proposalNonce);

        // Read the STORED window (public getter) BEFORE execution mutates status.
        (, uint256 storedValidAfter, uint256 storedValidUntil) =
            policy.getProposal(address(this), execCallData, proposalNonce, ID, address(this));

        // Execute the proposal.
        uint256 packed = policy.checkUserOpPolicy(ID, _executionUserOp(execCallData, proposalNonce));

        // Extract ERC-4337 bitfields.
        uint256 retValidAfter = packed >> 208; // bits 208-255
        uint256 retValidUntil = (packed >> 160) & type(uint48).max; // bits 160-207
        uint256 authorizer = packed & ((uint256(1) << 160) - 1); // bits 0-159

        // One property: returned window == stored window AND success (authorizer == 0).
        assertTrue(retValidAfter == storedValidAfter && retValidUntil == storedValidUntil && authorizer == 0);
    }

    // ---- Reachability / non-vacuity witness (MUST produce a counterexample) ----

    /// @notice Witness: a real Pending/current-epoch proposal with validUntil > validAfter is created
    ///         and executed to a SUCCESS leaf (authorizer bits == 0). Asserting that never happens must
    ///         yield a counterexample — proving the executed-window path is live (non-vacuous).
    function check_ExecReturnsStoredWindow_reachable(uint48 delay, uint48 expirationPeriod, uint256 proposalNonce)
        external
    {
        vm.assume(delay > 0);
        vm.assume(expirationPeriod > 0);
        vm.assume(block.timestamp <= type(uint48).max);
        vm.assume(uint256(delay) + uint256(expirationPeriod) <= uint256(type(uint48).max) - block.timestamp);

        bytes memory execCallData = hex"11223344";

        policy.onInstall(_installData(delay, expirationPeriod, address(0)));
        _commitAndCreate(execCallData, proposalNonce);

        (, uint256 storedValidAfter, uint256 storedValidUntil) =
            policy.getProposal(address(this), execCallData, proposalNonce, ID, address(this));

        uint256 packed = policy.checkUserOpPolicy(ID, _executionUserOp(execCallData, proposalNonce));
        uint256 authorizer = packed & ((uint256(1) << 160) - 1);

        // Live iff a model exists where: proposal window is strictly ordered (validUntil > validAfter)
        // AND execution succeeded (authorizer == 0). Assert the negation to expose the live path.
        assertFalse(storedValidUntil > storedValidAfter && authorizer == 0);
    }
}
