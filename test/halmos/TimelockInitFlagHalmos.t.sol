// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {TimelockPolicy} from "src/policies/TimelockPolicy.sol";

/// @author taek <leekt216@gmail.com>
/// @notice Halmos proof for TimelockPolicy install/uninstall init-flag round-trip (^req-20/^req-21).
/// @dev Target rebinding: the dispatch referenced a generic ERC-7579 module template
///      (`initialized[msg.sender]` at L79/L93, an `Initialized` emit). No such file exists here.
///      The concrete guard with the same error selectors (`IModule.AlreadyInitialized` /
///      `IModule.NotInitialized`) lives in TimelockPolicy._policyOninstall (L101) and
///      _policyOnUninstall (L125). The observable flag is `timelockConfig[id][account].initialized`;
///      the config-set path (the template's `Initialized` emit) is `TimelockConfigUpdated` at L118.
contract TimelockInitFlagHalmos is SymTest, Test {
    TimelockPolicy policy;

    function setUp() external {
        // Etch runtime code to avoid halmos-0.3.3 routing `new` through deployCode. No constructor state.
        policy = TimelockPolicy(address(0xACE));
        vm.etch(address(policy), type(TimelockPolicy).runtimeCode);
    }

    // onInstall entry: data = id(32) || abi.encode(delay, expirationPeriod, guardian)
    function _installData(bytes32 id, uint48 delay, uint48 expirationPeriod, address guardian)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(id, abi.encode(delay, expirationPeriod, guardian));
    }

    // onUninstall entry: data = id(32) || tail (tail unused by _policyOnUninstall)
    function _uninstallData(bytes32 id) internal pure returns (bytes memory) {
        return abi.encodePacked(id);
    }

    function _initialized(bytes32 id) internal view returns (bool) {
        (,,, bool init) = policy.timelockConfig(id, address(this));
        return init;
    }

    // Precondition: keep the uint48 overflow guard (L108) satisfiable so onInstall can succeed.
    function _validParams(uint48 delay, uint48 expirationPeriod) internal view {
        vm.assume(delay > 0);
        vm.assume(expirationPeriod > 0);
        vm.assume(block.timestamp <= type(uint48).max);
        vm.assume(uint256(delay) + uint256(expirationPeriod) <= uint256(type(uint48).max) - block.timestamp);
    }

    /// @notice ROUND-TRIP IDEMPOTENCE (^req-20/^req-21): starting from an uninitialized (id, account),
    ///         onInstall sets the flag true and a following onUninstall restores it to false — the flag
    ///         returns to its pre-install value. Observable via the public timelockConfig getter, not a
    ///         recompute of the guard boolean.
    function check_InitFlagRoundTrip(bytes32 id, uint48 delay, uint48 expirationPeriod, address guardian) external {
        _validParams(delay, expirationPeriod);
        // Precondition: (id, this) starts uninitialized (the fresh-install branch).
        vm.assume(!_initialized(id));

        policy.onInstall(_installData(id, delay, expirationPeriod, guardian));
        bool afterInstall = _initialized(id);

        policy.onUninstall(_uninstallData(id));
        bool afterUninstall = _initialized(id);

        // Single load-bearing assertion: install toggled true then uninstall toggled false.
        // Encoded as one boolean so it is exactly one property (round-trip == install-set && uninstall-clear).
        assertTrue(afterInstall && !afterUninstall);
    }

    // ---- Reachability / non-vacuity witness (MUST produce a counterexample) ----

    /// @notice Witness: the successful onInstall path (initialized false -> true, reaching the
    ///         TimelockConfigUpdated / config-set leaf) is LIVE. Asserting the post-install flag is
    ///         never true must fail — exposing a real model where install succeeds.
    function check_InitFlagRoundTrip_reachable(bytes32 id, uint48 delay, uint48 expirationPeriod, address guardian)
        external
    {
        _validParams(delay, expirationPeriod);
        vm.assume(!_initialized(id));

        policy.onInstall(_installData(id, delay, expirationPeriod, guardian));

        // Live iff a model exists with the flag set post-install: assert it never is to expose it.
        assertFalse(_initialized(id));
    }
}
