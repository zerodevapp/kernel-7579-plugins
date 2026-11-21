// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {DefaultSecurityHook} from "src/hooks/DefaultSecurityHook.sol";
import {IModule} from "src/interfaces/IERC7579Modules.sol";

// Minimal cheatcode surface. Inheriting forge-std `Test` pulls in a base constructor that calls
// vm.deployCode(string) (StdConfig), which Halmos 0.3.3 does not support and fails setUp().
interface Vm {
    function assume(bool) external pure;
    function prank(address) external;
    function etch(address, bytes calldata) external;
}

/// @author taek <leekt216@gmail.com>
/// @notice Halmos proof harness for INV-07 leg (a): the re-initialization guard on onInstall
///         (DefaultSecurityHook.sol:79). A second onInstall from an already-initialized account
///         MUST revert with exactly AlreadyInitialized(account) — it must not succeed and must
///         not re-enter the config-decode loop. Empty first-install data isolates the guard from
///         config parsing (data.length==0 branch, :82). Own file/contract (etch-deploy pattern
///         identical to the sibling DefaultSecurityHook Halmos harnesses; no constructor logic).
contract DefaultSecurityHookDoubleInstallHalmos is SymTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    DefaultSecurityHook internal hook;

    function setUp() external {
        hook = DefaultSecurityHook(address(uint160(uint256(keccak256("DefaultSecurityHook")))));
        vm.etch(address(hook), type(DefaultSecurityHook).runtimeCode);
    }

    /// @notice OBSERVABLE (INV-07 leg a): a fresh symbolic account runs a real onInstall("") that
    ///         succeeds and flips isInitialized(account)==true; a SECOND onInstall(<any data>)
    ///         from the same account reverts with exactly AlreadyInitialized(account). Asserts the
    ///         external revert-vs-success observable and the error selector literal only — it does
    ///         not read the `initialized[msg.sender]` slot nor recompute the guard condition
    ///         (non-tautological). Source: DefaultSecurityHook.sol:79.
    function check_DoubleInstallReverts() external {
        address account = svm.createAddress("account");
        bytes memory secondData = svm.createBytes(256, "secondData");

        // Genuine spec precondition: a fresh account defaults to initialized==false.
        vm.assume(!hook.isInitialized(account));

        // First install: empty data => decode loop skipped, guard flips the flag.
        vm.prank(account);
        hook.onInstall("");

        // Second install with ANY data must be rejected by the guard.
        vm.prank(account);
        (bool ok, bytes memory ret) = address(hook).call(abi.encodeCall(hook.onInstall, (secondData)));

        assert(!ok);
        assert(keccak256(ret) == keccak256(abi.encodeWithSelector(IModule.AlreadyInitialized.selector, account)));
    }

    /// @notice Reachability/vacuity witness (SAME precondition set): proves (1) the uninitialized
    ///         precondition is satisfiable — a fresh account exists — and (2) the FIRST onInstall
    ///         SUCCESS branch is genuinely taken, flipping isInitialized(account)==true on the
    ///         live (non-reverting) path. Guards on that live branch then asserts false so Halmos
    ///         MUST emit a counterexample; NO counterexample => the first install reverted or the
    ///         precondition is unsatisfiable (VACUOUS — report as such, not proven).
    function check_DoubleInstallReverts_reachable() external {
        address account = svm.createAddress("account");

        // (1) satisfiability: a fresh, uninitialized account exists.
        vm.assume(!hook.isInitialized(account));

        // (2) path-liveness: the first-install SUCCESS branch is genuinely taken.
        vm.prank(account);
        hook.onInstall("");

        if (hook.isInitialized(account)) {
            assert(false);
        }
    }
}
