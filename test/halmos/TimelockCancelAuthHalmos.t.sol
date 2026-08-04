// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {TimelockPolicy} from "src/policies/TimelockPolicy.sol";

/// @author taek <leekt216@gmail.com>
/// @notice Halmos proof: guardian is cancellation-only, per-account scoped.
/// @dev Property: cancelProposal's auth gate (TimelockPolicy.sol:152) passes IFF
///        msg.sender == account OR (guardian != 0 && msg.sender == guardian)
///      where guardian is read per (id, account) from timelockConfig[id][account].guardian (:151).
///      Any other caller reverts OnlyAccount. This is the observable revert-vs-pass of the auth
///      gate — asserted against the authorization predicate in BOTH directions (:154-167 is only
///      reachable when the gate passes; a Pending proposal is seeded so the pass path does not
///      immediately hit ProposalNotPending at :161).
contract TimelockCancelAuthHalmos is SymTest, Test {
    TimelockPolicy policy;

    function setUp() external {
        // Etch runtime code: halmos 0.3.3 cannot route `new` through deployCode. Empty ctor state.
        policy = TimelockPolicy(address(0xACE));
        vm.etch(address(policy), type(TimelockPolicy).runtimeCode);
    }

    // proposals slot = 2. base = keccak(account, keccak(id, keccak(userOpKey, 2))).
    // Proposal packs {status(uint8), validAfter(uint48), validUntil(uint48)} into base slot;
    // epoch(uint256) into base+1. Writing base = 1 => status = Pending, rest zero.
    function _seedPending(bytes32 userOpKey, bytes32 id, address account) internal {
        bytes32 s1 = keccak256(abi.encode(userOpKey, uint256(2)));
        bytes32 s2 = keccak256(abi.encode(id, s1));
        bytes32 base = keccak256(abi.encode(account, s2));
        vm.store(address(policy), base, bytes32(uint256(1))); // ProposalStatus.Pending == 1
    }

    // Install config for `account` (sets initialized=true and guardian) by pranking as account.
    function _install(bytes32 id, address account, address guardian) internal {
        bytes memory data = abi.encodePacked(id, abi.encode(uint48(1), uint48(1), guardian));
        vm.prank(account);
        policy.onInstall(data);
    }

    // The authorization predicate exactly as coded at :152 (negated -> revert).
    function _authorized(address caller, address account, address guardian) internal pure returns (bool) {
        return caller == account || (guardian != address(0) && caller == guardian);
    }

    /// @notice cancelProposal reverts OnlyAccount IFF the caller is not authorized, i.e. it succeeds
    ///         (proposal -> Cancelled) exactly when msg.sender==account OR (guardian!=0 &&
    ///         msg.sender==guardian) for that per-account config. One boolean: revert-iff-unauthorized.
    function check_CancelAuthGate(
        bytes32 id,
        address account,
        address caller,
        address guardian,
        bytes calldata callData,
        uint256 nonce
    ) external {
        // account must be able to install (guard at :101 needs a fresh, non-etch-address account is fine).
        vm.assume(account != address(policy));
        _install(id, account, guardian);

        // Seed a Pending proposal for the exact key cancelProposal computes, so an authorized caller
        // reaches the Cancelled write (:165) instead of ProposalNotPending (:161).
        bytes32 userOpKey = keccak256(abi.encode(account, keccak256(callData), nonce));
        _seedPending(userOpKey, id, account);

        bool wantAuth = _authorized(caller, account, guardian);

        vm.prank(caller);
        try policy.cancelProposal(id, account, callData, nonce) {
            // Success path is reachable ONLY when the auth gate passed.
            assertTrue(wantAuth);
        } catch (bytes memory reason) {
            // Must be OnlyAccount() and only when unauthorized.
            assertEq(bytes4(reason), TimelockPolicy.OnlyAccount.selector);
            assertFalse(wantAuth);
        }
    }

    // ---- Reachability / non-vacuity witnesses (each MUST produce a counterexample) ----

    /// @notice Witness: the ACCOUNT-caller pass path is live (msg.sender==account -> Cancelled).
    ///         Assert it never succeeds to expose a live model.
    function check_CancelAuthGate_reachable_account(
        bytes32 id,
        address account,
        address guardian,
        bytes calldata callData,
        uint256 nonce
    ) external {
        vm.assume(account != address(policy));
        _install(id, account, guardian);
        bytes32 userOpKey = keccak256(abi.encode(account, keccak256(callData), nonce));
        _seedPending(userOpKey, id, account);

        vm.prank(account);
        policy.cancelProposal(id, account, callData, nonce);
        // Live iff a model exists where account-caller cancels: getter shows Cancelled(3).
        (TimelockPolicy.ProposalStatus status,,) = policy.getProposal(account, callData, nonce, id, account);
        assertTrue(status != TimelockPolicy.ProposalStatus.Cancelled);
    }

    /// @notice Witness: the GUARDIAN-caller pass path is live (guardian!=0, msg.sender==guardian,
    ///         guardian!=account -> Cancelled). Assert it never succeeds to expose a live model.
    function check_CancelAuthGate_reachable_guardian(
        bytes32 id,
        address account,
        address guardian,
        bytes calldata callData,
        uint256 nonce
    ) external {
        vm.assume(account != address(policy));
        vm.assume(guardian != address(0));
        vm.assume(guardian != account);
        _install(id, account, guardian);
        bytes32 userOpKey = keccak256(abi.encode(account, keccak256(callData), nonce));
        _seedPending(userOpKey, id, account);

        vm.prank(guardian);
        policy.cancelProposal(id, account, callData, nonce);
        (TimelockPolicy.ProposalStatus status,,) = policy.getProposal(account, callData, nonce, id, account);
        assertTrue(status != TimelockPolicy.ProposalStatus.Cancelled);
    }

    /// @notice Witness: the UNAUTHORIZED-revert path is live (caller != account, and either no
    ///         guardian or caller != guardian -> OnlyAccount). Assert cancel always succeeds to
    ///         expose the reverting model.
    function check_CancelAuthGate_reachable_revert(
        bytes32 id,
        address account,
        address caller,
        address guardian,
        bytes calldata callData,
        uint256 nonce
    ) external {
        vm.assume(account != address(policy));
        vm.assume(caller != account);
        vm.assume(guardian == address(0) || caller != guardian);
        _install(id, account, guardian);
        bytes32 userOpKey = keccak256(abi.encode(account, keccak256(callData), nonce));
        _seedPending(userOpKey, id, account);

        vm.prank(caller);
        // Live iff a model exists that reaches the OnlyAccount revert: assert-false in the catch
        // yields a counterexample, proving the unauthorized-revert path is reachable.
        try policy.cancelProposal(id, account, callData, nonce) {
            assertTrue(true);
        } catch (bytes memory reason) {
            assertEq(bytes4(reason), TimelockPolicy.OnlyAccount.selector);
            assertFalse(true);
        }
    }
}
