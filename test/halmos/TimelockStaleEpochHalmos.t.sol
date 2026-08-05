// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {TimelockPolicy} from "src/policies/TimelockPolicy.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_FAILED_UINT} from "src/types/Constants.sol";

/// @author taek <leekt216@gmail.com>
/// @notice Halmos proof (stale-proposal replay, epoch-mismatch leg): a proposal created under a
///         prior installation can NEVER validate for execution after reinstall. Concretely,
///         _handleProposalExecutionInternal (reached via checkUserOpPolicy with matching non-no-op
///         callData/nonce) returns SIG_VALIDATION_FAILED_UINT whenever proposal.epoch !=
///         currentEpoch[id][account].
/// @dev Property source: TimelockPolicy._policyOninstall bumps currentEpoch (L113
///      `currentEpoch[id][msg.sender]++`); _handleProposalCreationInternal stamps proposal.epoch =
///      currentEpoch (L231); _handleProposalExecutionInternal rejects on mismatch (L256
///      `if (proposal.epoch != currentEpoch[id][account]) return SIG_VALIDATION_FAILED_UINT`).
///      The stale cross-epoch state is produced through the REAL trace: install (epoch E) -> create
///      Pending proposal at epoch E -> uninstall -> reinstall (epoch E+1). The assertion checks the
///      OBSERVABLE return sentinel (== SIG_VALIDATION_FAILED_UINT), not a recompute of the epoch
///      counter.
///      DEPLOY: vm.etch of runtimeCode (empty ctor) — sound for halmos-0.3.3 which cannot route `new`
///      through deployCode.
contract TimelockStaleEpochHalmos is SymTest, Test {
    TimelockPolicy policy;

    bytes32 constant ID = bytes32(uint256(0x7e10c0));

    function setUp() external {
        policy = TimelockPolicy(address(0xACE));
        vm.etch(address(policy), type(TimelockPolicy).runtimeCode);
    }

    function _installData(uint48 delay, uint48 expirationPeriod, address guardian)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(ID, abi.encode(delay, expirationPeriod, guardian));
    }

    // no-op callData => proposal CREATION; signature = [callDataLength(32)][callData][nonce(32)].
    function _creationUserOp(bytes memory execCallData, uint256 proposalNonce)
        internal
        view
        returns (PackedUserOperation memory op)
    {
        op.sender = address(this);
        op.nonce = 0;
        op.callData = "";
        op.signature = abi.encodePacked(uint256(execCallData.length), execCallData, proposalNonce);
    }

    // non-no-op callData + matching nonce => EXECUTION of proposal keyed by keccak(sender, keccak(callData), nonce).
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

    /// @notice A proposal created before a reinstall (epoch E) can never execute after reinstall
    ///         (epoch E+1): execution returns the failure sentinel. One load-bearing assertion.
    function check_StaleEpochProposalRejected(uint48 delay, uint48 expirationPeriod, uint256 proposalNonce) external {
        // Genuine preconditions: install guard satisfiable (else onInstall reverts, not a real state).
        vm.assume(delay > 0);
        vm.assume(expirationPeriod > 0);
        vm.assume(block.timestamp <= type(uint48).max);
        vm.assume(uint256(delay) + uint256(expirationPeriod) <= uint256(type(uint48).max) - block.timestamp);

        bytes memory execCallData = hex"11223344"; // non-no-op

        // Install #1 -> epoch E. Create Pending proposal stamped at epoch E.
        policy.onInstall(_installData(delay, expirationPeriod, address(0)));
        policy.checkUserOpPolicy(ID, _creationUserOp(execCallData, proposalNonce));

        // Reinstall: uninstall (config deleted, currentEpoch persists) then install #2 -> epoch E+1.
        policy.onUninstall(abi.encodePacked(ID, bytes("")));
        policy.onInstall(_installData(delay, expirationPeriod, address(0)));

        // Attempt to execute the stale (epoch E) proposal under the reinstalled config (epoch E+1).
        uint256 result = policy.checkUserOpPolicy(ID, _executionUserOp(execCallData, proposalNonce));

        // OBSERVABLE postcondition: the failure sentinel, never a success window.
        assertEq(result, SIG_VALIDATION_FAILED_UINT);
    }

    // ---- Reachability / non-vacuity witness (MUST produce a counterexample) ----

    /// @notice Witness that the stale cross-epoch state is genuinely reachable AND that, absent the
    ///         reinstall, the SAME proposal WOULD execute to success — so the L256 epoch check is a
    ///         real discriminator, not because execution always fails. We assert false on the
    ///         SUCCESS leaf of the no-reinstall path; a counterexample proves that path is live.
    function check_StaleEpochProposalRejected_reachable(uint48 delay, uint48 expirationPeriod, uint256 proposalNonce)
        external
    {
        vm.assume(delay > 0);
        vm.assume(expirationPeriod > 0);
        vm.assume(block.timestamp <= type(uint48).max);
        vm.assume(uint256(delay) + uint256(expirationPeriod) <= uint256(type(uint48).max) - block.timestamp);

        bytes memory execCallData = hex"11223344";

        // Same install + create, but NO reinstall: proposal.epoch == currentEpoch.
        policy.onInstall(_installData(delay, expirationPeriod, address(0)));
        policy.checkUserOpPolicy(ID, _creationUserOp(execCallData, proposalNonce));

        uint256 result = policy.checkUserOpPolicy(ID, _executionUserOp(execCallData, proposalNonce));

        // Live iff a model exists where the matching-epoch proposal executes to a SUCCESS window
        // (authorizer bits == 0). Assert the negation to expose the live success path.
        uint256 authorizer = result & ((uint256(1) << 160) - 1);
        assertFalse(authorizer == 0 && result != SIG_VALIDATION_FAILED_UINT);
    }
}
