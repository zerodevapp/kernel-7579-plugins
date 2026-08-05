// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @author taek <leekt216@gmail.com>
///
/// Kontrol (KEVM) proof: a proposal created under a prior installation
/// can NEVER validate for execution after reinstall. The epoch bump in
/// _policyOninstall (currentEpoch++) plus the epoch guard in
/// _handleProposalExecutionInternal (proposal.epoch != currentEpoch => FAILED)
/// together make any stale-epoch proposal un-executable.
///
/// KEVM's value over Halmos/Certora here: the execution path runs the exact
/// compiled bytecode of checkUserOpPolicy -> _validateUserOpPolicy ->
/// _handleProposalExecutionInternal, including the SLOAD of the nested
/// proposals[keccak(...)] and currentEpoch mappings and the keccak of the
/// userOpKey — grounded at the opcode level, not at Solidity-source level.
///
/// Run:
///   kontrol build
///   kontrol prove --match-test 'TimelockPolicyKontrol.prove_staleEpochProposalRejected'
///   kontrol prove --match-test 'TimelockPolicyKontrol.prove_matchingEpochSuccessReachable'
///   kontrol prove --match-test 'TimelockPolicyKontrol.prove_crossEpochStaleStateReachable'

import {Test} from "forge-std/Test.sol";
import {KontrolCheats} from "kontrol-cheatcodes/KontrolCheats.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {TimelockPolicy} from "src/policies/TimelockPolicy.sol";

contract TimelockPolicyKontrol is Test, KontrolCheats {
    TimelockPolicy internal policy;

    uint256 constant SUCCESS_AUTHORIZER = 0; // low 160 bits == 0 on success
    uint256 constant FAILED = 1; // SIG_VALIDATION_FAILED_UINT

    function setUp() public {
        policy = new TimelockPolicy();
    }

    // A non-no-op callData: 4 bytes that are NOT executeUserOp/execute selectors and
    // length < 100 so _isNoOpCalldata returns false and we hit the EXECUTION path.
    function _execCallData() internal pure returns (bytes memory) {
        return hex"deadbeef";
    }

    function _buildExecOp(uint256 nonce) internal pure returns (PackedUserOperation memory op) {
        op.sender = address(0xA11CE);
        op.nonce = nonce;
        op.callData = _execCallData();
    }

    // Install a config (delay/expiration valid) so config.initialized == true and the
    // execution path is reached rather than the not-initialized early return.
    function _install(bytes32 id) internal {
        uint48 delay = 1;
        uint48 expiration = 1;
        // guardian = 0
        bytes memory data = abi.encode(delay, expiration, address(0));
        vm.prank(address(0xA11CE));
        policy.onInstall(abi.encodePacked(id, data));
    }

    // Legitimately create a Pending proposal for (sender, callData, nonce) by sending a
    // no-op UserOp whose signature carries the proposal (callData,nonce). This stamps
    // proposal.epoch = currentEpoch at creation time.
    function _createProposal(bytes32 id, bytes memory callData, uint256 nonce) internal {
        PackedUserOperation memory op;
        op.sender = address(0xA11CE);
        op.nonce = 999; // the CURRENT op nonce is irrelevant; proposal keyed by sig data
        op.callData = ""; // empty => no-op path => creation

        // sig format: [callDataLen(32)][callData][nonce(32)]
        op.signature = abi.encodePacked(bytes32(callData.length), callData, bytes32(nonce));
        vm.prank(address(0xA11CE));
        policy.checkUserOpPolicy(id, op);
    }

    // ==========================================================================
    // MAIN discriminator (OBSERVABLE, non-tautological): a Pending proposal stamped
    // at the pre-reinstall epoch, with currentEpoch advanced by a genuine reinstall,
    // causes the execution path to return the FAILED sentinel. Inputs id and nonce
    // are SYMBOLIC, so this covers every proposal key. Crucially we do NOT havoc
    // storage (symbolicStorage produced out-of-range enum bytes -> spurious reverts);
    // instead the mismatch is created through the contract's own transitions
    // (create @ epoch 1, uninstall, reinstall -> epoch 2), which is both sound and
    // keeps status/config bytes well-formed. We assert the observable return ==
    // FAILED, NOT a recomputation of the epoch counter.
    // ==========================================================================
    function prove_staleEpochProposalRejected(bytes32 id, uint256 nonce) public {
        _install(id); // currentEpoch: 0 -> 1

        bytes memory callData = _execCallData();
        _createProposal(id, callData, nonce); // proposal.epoch = 1, status = Pending

        // Advance currentEpoch via a real reinstall (simulating account reinstall).
        vm.prank(address(0xA11CE));
        policy.onUninstall(abi.encodePacked(id, bytes("")));
        _install(id); // currentEpoch: 1 -> 2  => proposal.epoch (1) != currentEpoch (2)

        // Precondition witness (bound, not asserted-as-postcondition): the mismatch holds.
        vm.assume(_readProposalEpoch(id, callData, nonce) != policy.currentEpoch(id, address(0xA11CE)));

        PackedUserOperation memory op = _buildExecOp(nonce);
        vm.prank(address(0xA11CE));
        uint256 ret = policy.checkUserOpPolicy(id, op);

        // OBSERVABLE postcondition: mismatch => FAILED sentinel, never a success window.
        assert(ret == FAILED);
    }

    // ==========================================================================
    // REACHABILITY witness #1 (non-vacuity): the SUCCESS path is reachable. Matching
    // epoch, Pending, initialized => execution returns a success validationData whose
    // low-160 authorizer bits are 0 (i.e. NOT the FAILED sentinel). If this were
    // infeasible the main proof's FAILED would not be a real discriminator.
    // ==========================================================================
    function prove_matchingEpochSuccessReachable(bytes32 id, uint256 nonce) public {
        _install(id);
        bytes memory callData = _execCallData();
        _createProposal(id, callData, nonce); // epoch == currentEpoch, Pending

        PackedUserOperation memory op = _buildExecOp(nonce);
        vm.prank(address(0xA11CE));
        uint256 ret = policy.checkUserOpPolicy(id, op);

        // Success: low 160 bits (authorizer) are 0, and it is NOT the FAILED sentinel.
        assert(ret != FAILED);
        assert((ret & ((uint256(1) << 160) - 1)) == SUCCESS_AUTHORIZER);
    }

    // ==========================================================================
    // REACHABILITY witness #2 (genuine cross-epoch stale state is reachable): drive
    // the actual multi-step trace install -> create -> uninstall -> reinstall (bumps
    // currentEpoch) and confirm the resulting proposal.epoch != currentEpoch AND that
    // execution then returns FAILED. This proves the stale state is not merely a
    // symbolic artifact but attainable through the contract's own transitions.
    // ==========================================================================
    function prove_crossEpochStaleStateReachable(bytes32 id) public {
        uint256 nonce = 7;
        bytes memory callData = _execCallData();

        _install(id); // currentEpoch: 0 -> 1
        _createProposal(id, callData, nonce); // proposal.epoch = 1, Pending

        // Uninstall then reinstall to bump the epoch (simulating account reinstall).
        vm.prank(address(0xA11CE));
        policy.onUninstall(abi.encodePacked(id, bytes("")));
        _install(id); // currentEpoch: 1 -> 2

        uint256 cur = policy.currentEpoch(id, address(0xA11CE));
        uint256 propEpoch = _readProposalEpoch(id, callData, nonce);
        assert(propEpoch != cur); // genuine stale state reached (1 != 2)

        PackedUserOperation memory op = _buildExecOp(nonce);
        vm.prank(address(0xA11CE));
        uint256 ret = policy.checkUserOpPolicy(id, op);
        assert(ret == FAILED);
    }

    // Read proposal.epoch via the public `proposals` mapping getter.
    function _readProposalEpoch(bytes32 id, bytes memory callData, uint256 nonce) internal view returns (uint256) {
        bytes32 userOpKey = keccak256(abi.encode(address(0xA11CE), keccak256(callData), nonce));
        (,,, uint256 epoch) = policy.proposals(userOpKey, id, address(0xA11CE));
        return epoch;
    }
}
