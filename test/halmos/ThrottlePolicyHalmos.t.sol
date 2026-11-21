// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {ThrottlePolicy} from "src/policies/ThrottlePolicy.sol";
import {ValidAfter} from "src/types/Types.sol";
import {SIG_VALIDATION_FAILED_UINT} from "src/types/Constants.sol";

/// @author taek <leekt216@gmail.com>
/// @notice Halmos proofs for ThrottlePolicy anchoring.
contract ThrottlePolicyHalmos is SymTest, Test {
    ThrottlePolicy policy;

    function setUp() external {
        // Deploy via etch of deployed bytecode: halmos 0.3.3 + foundry-nightly can route `new`
        // through the unsupported deployCode(string) cheat, so avoid CREATE. ThrottlePolicy has no
        // constructor state, so etching the runtime code is a faithful deployment.
        policy = ThrottlePolicy(address(0xACE));
        vm.etch(address(policy), _throttleRuntime());
    }

    function _throttleRuntime() internal returns (bytes memory) {
        // deployedBytecode of ThrottlePolicy (out/ThrottlePolicy.sol/ThrottlePolicy.json).
        return type(ThrottlePolicy).runtimeCode;
    }

    // Installs a Live config with symbolic interval/count/startAt for `id`, sender = this harness.
    function _install(bytes32 id, uint48 interval, uint48 count, uint48 startAt) internal {
        policy.onInstall(abi.encodePacked(id, interval, count, startAt));
    }

    function _emptyOp() internal pure returns (PackedUserOperation memory op) {}

    /// @notice ANCHOR (A): after an accepted checkUserOpPolicy the STORED next startAt equals
    ///         max(now, oldStartAt) + interval — an idle gap (now > oldStartAt) is NOT banked.
    function check_AnchorNextSlotToNow(bytes32 id, uint48 interval, uint48 count, uint48 startAt) external {
        vm.assume(count > 0);
        // block.timestamp is symbolic; keep the uint48 cast faithful (no silent truncation).
        vm.assume(block.timestamp <= type(uint48).max);
        uint48 now48 = uint48(block.timestamp);
        uint48 anchored = now48 > startAt ? now48 : startAt;
        // interval chosen so anchored + interval does not overflow uint48 (dispatch precondition).
        vm.assume(uint256(anchored) + uint256(interval) <= type(uint48).max);

        _install(id, interval, count, startAt);

        uint256 ret = policy.checkUserOpPolicy(id, _emptyOp());
        vm.assume(ret != SIG_VALIDATION_FAILED_UINT); // accepted op only

        (,, ValidAfter newStartAt) = policy.throttleConfigs(id, address(this));
        // Single load-bearing assertion: the stored slot is anchored to max(now, oldStartAt).
        assertEq(ValidAfter.unwrap(newStartAt), anchored + interval);
    }

    // ---- Reachability / non-vacuity witnesses (must produce counterexamples) ----

    /// @notice Witness (i): the IDLE branch is live — a state where now > oldStartAt and the
    ///         stored slot becomes now + interval exists. Asserting false must fail.
    function check_AnchorNextSlotToNow_reachable(bytes32 id, uint48 interval, uint48 count, uint48 startAt) external {
        vm.assume(count > 0);
        vm.assume(block.timestamp <= type(uint48).max);
        uint48 now48 = uint48(block.timestamp);
        vm.assume(now48 > startAt); // force the idle-gap branch specifically
        vm.assume(uint256(now48) + uint256(interval) <= type(uint48).max);

        _install(id, interval, count, startAt);
        uint256 ret = policy.checkUserOpPolicy(id, _emptyOp());
        vm.assume(ret != SIG_VALIDATION_FAILED_UINT);

        (,, ValidAfter newStartAt) = policy.throttleConfigs(id, address(this));
        // Path is live iff a model exists with newStartAt == now + interval: assert false to expose it.
        assertNotEq(ValidAfter.unwrap(newStartAt), now48 + interval);
    }

    /// @notice Witness (ii): the BUDGET gate is live — a config with count==1 exists whose next
    ///         call (count now 0) returns FAILED. Asserting the terminal reject never happens must fail.
    function check_BudgetGateReject_reachable(bytes32 id, uint48 interval, uint48 startAt) external {
        vm.assume(block.timestamp <= type(uint48).max);
        uint48 now48 = uint48(block.timestamp);
        uint48 anchored = now48 > startAt ? now48 : startAt;
        vm.assume(uint256(anchored) + uint256(interval) <= type(uint48).max);

        _install(id, interval, 1, startAt); // budget of exactly one

        // first op accepted, decrements count 1 -> 0
        uint256 first = policy.checkUserOpPolicy(id, _emptyOp());
        vm.assume(first != SIG_VALIDATION_FAILED_UINT);

        // second op must hit the count==0 gate
        uint256 second = policy.checkUserOpPolicy(id, _emptyOp());
        // Reject is live iff a model exists with second == FAILED: assert it never does to expose it.
        assertNotEq(second, SIG_VALIDATION_FAILED_UINT);
    }
}
