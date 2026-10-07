// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {StdAssertions} from "forge-std/StdAssertions.sol";
import {Vm} from "forge-std/Vm.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {RateLimitPolicy} from "src/policies/RateLimitPolicy.sol";

/// @author taek <leekt216@gmail.com>
/// @notice Halmos proof for RateLimitPolicy: storedCount never exceeds the configured initialCount cap.
/// @dev Inherits StdAssertions (not Test) — forge-std 1.11 Test.setUp triggers an unsupported
///      deployCode cheatcode under halmos 0.3.3, aborting every path in setUp().
///      The contract-under-test is placed via `vm.etch(runtimeCode)` rather than `new`: under
///      foundry nightly 1.7.2 halmos 0.3.3 lowers `new C()` to the unsupported deployCode(string)
///      cheatcode, and raw CREATE hits an artifact-path mismatch. RateLimitPolicy has an empty
///      constructor (no immutables / no ctor state), so etching runtime code is behaviorally identical.
contract RateLimitPolicyHalmos is SymTest, StdAssertions {
    // hevm cheat-code address; StdAssertions declares its own `vm` privately, so redeclare here.
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    RateLimitPolicy internal constant policy = RateLimitPolicy(address(0xBEEF));

    function setUp() external {
        vm.etch(address(policy), type(RateLimitPolicy).runtimeCode);
    }

    // Installs a Live config with symbolic interval/initialCount for `id`, sender = this harness.
    function _install(bytes32 id, uint48 interval, uint48 initialCount) internal {
        policy.onInstall(abi.encodePacked(id, interval, initialCount));
    }

    function _emptyOp() internal pure returns (PackedUserOperation memory op) {}

    function _initialCount(bytes32 id) internal view returns (uint48) {
        (, uint48 initialCount) = policy.rateLimitConfigs(id, address(this));
        return initialCount;
    }

    function _storedCount(bytes32 id) internal view returns (uint48) {
        (uint48 storedCount,) = policy.rateLimitState(id, address(this));
        return storedCount;
    }

    // storage slot of rateLimitState[id][address(this)].
    // rateLimitState is the 3rd declared mapping in RateLimitPolicy => base slot 2 (confirmed via forge inspect).
    function _stateSlot(bytes32 id) internal view returns (bytes32) {
        bytes32 inner = keccak256(abi.encode(id, uint256(2)));
        return keccak256(abi.encode(address(this), inner));
    }

    /// @notice (A) INDUCTIVE INVARIANT: if the pre-state already respects the cap
    ///         (storedCount <= initialCount), then after checkUserOpPolicy the cap still holds,
    ///         for any symbolic block.timestamp. The reset branch writes exactly initialCount and
    ///         the no-reset branch only decrements, so neither branch can exceed the cap.
    /// @dev Symbolic pre-state: after install we overwrite storedCount/resetDate with fresh symbolic
    ///      values (an ARBITRARY state, not just the freshly-installed one). The cap is the loop
    ///      invariant of every reachable trace: storedCount is only ever written to `initialCount`
    ///      (install/reset) then decremented, so `preStored <= initialCount` is the exact inductive
    ///      hypothesis — it is a precondition of every reachable pre-state, NOT a weakening. (A run
    ///      without it produces the expected counterexample of a fabricated storedCount > initialCount,
    ///      which is not a reachable state.)
    function check_StoredCountNeverExceedsCap(
        bytes32 id,
        uint48 interval,
        uint48 initialCount,
        uint48 preStored,
        uint48 preReset
    ) external {
        // install to make config Live, then plant an arbitrary state respecting the inductive hypothesis
        _install(id, interval, initialCount);
        vm.assume(preStored <= initialCount); // inductive hypothesis: cap held in the pre-state
        vm.store(address(policy), _stateSlot(id), bytes32((uint256(preReset) << 48) | uint256(preStored)));
        // sanity: the plant round-trips (guards against a slot-layout mistake making this vacuous)
        require(_storedCount(id) == preStored);

        policy.checkUserOpPolicy(id, _emptyOp());

        // Single load-bearing assertion: stored <= config cap (observable storage <= config field).
        assertLe(uint256(_storedCount(id)), uint256(_initialCount(id)));
    }

    // ---- Reachability / non-vacuity witnesses (must produce counterexamples) ----

    /// @notice Witness (i) — BUDGET GATE is live (supports claim B): a same-window sequence that
    ///         exhausts the budget reverts RateLimited() on the exhausting call. With initialCount==1
    ///         and no reset crossing, the first call is accepted and the second reverts. Proving the
    ///         second call NEVER reverts must fail, exposing the live reject path.
    function check_BudgetGateReject_reachable(bytes32 id, uint48 interval) external {
        vm.assume(block.timestamp <= type(uint48).max);
        uint48 now48 = uint48(block.timestamp);
        // stay inside one window on the second call: resetDate stays in the future.
        vm.assume(uint256(now48) + uint256(interval) <= type(uint48).max);

        _install(id, interval, 1); // budget of exactly one, resetDate = now + interval

        policy.checkUserOpPolicy(id, _emptyOp()); // first: accepted, stored 1 -> 0

        // second call: now < resetDate (same window) so no refill, stored==0 -> must revert
        try policy.checkUserOpPolicy(id, _emptyOp()) returns (uint256) {
            assertTrue(true); // non-reverting path
        } catch {
            assertTrue(false); // fails => a reverting model exists => gate is reachable
        }
    }

    /// @notice Witness (ii) — RESET LIVENESS is live (supports claim C): a call with now >= resetDate
    ///         refills storedCount to initialCount. Starting from a drained/expired state, the call
    ///         must refill. Proving stored != initialCount-1 after the refill+decrement must fail,
    ///         exposing the live reset path.
    function check_ResetRefill_reachable(bytes32 id, uint48 interval, uint48 initialCount) external {
        vm.assume(initialCount > 0);
        vm.assume(block.timestamp <= type(uint48).max);
        uint48 now48 = uint48(block.timestamp);
        vm.assume(uint256(now48) + uint256(interval) <= type(uint48).max); // reset push no overflow

        _install(id, interval, initialCount);
        // drain and expire: stored==0, resetDate==0 (<= now) => next call crosses the reset.
        vm.store(address(policy), _stateSlot(id), bytes32(uint256(0)));

        policy.checkUserOpPolicy(id, _emptyOp()); // crosses reset: refill to initialCount, then --

        // reset is live iff a model exists where the refill happened (stored == initialCount - 1);
        // assert it never does to expose the reachable refill path.
        assertNotEq(uint256(_storedCount(id)), uint256(initialCount - 1));
    }
}
