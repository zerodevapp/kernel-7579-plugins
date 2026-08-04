// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {DefaultSecurityHook} from "src/hooks/DefaultSecurityHook.sol";

// Minimal cheatcode surface. Inheriting forge-std `Test` pulls in a base constructor that calls
// vm.deployCode(string) (StdConfig), which Halmos 0.3.3 does not support and fails setUp().
interface Vm {
    function assume(bool) external pure;
    function prank(address) external;
    function etch(address, bytes calldata) external;
}

/// @author taek <leekt216@gmail.com>
/// @notice Halmos proof harness for the DefaultSecurityHook module-call deny gate (_checkCall :196,
///         spec §4.3). Own file/contract per the per-gate convention (see DenyETH harness); the
///         etch-deploy pattern is identical and state-equivalent (DefaultSecurityHook has no
///         constructor logic, all state via onInstall).
///
///         Property: for a SINGLE call to a target that is NOT allowlisted and NOT the caller,
///         whose isModuleType(0) staticcall SUCCEEDS within the 30k stipend (_isModule==true),
///         preCheck reverts ModuleCallNotAllowed(target) for ALL symbolic (value, selector) —
///         including value>0 and blocked token selectors, pinning the §5.2 check order (module
///         check :196 precedes ETH :199 and selector :202 checks).
///
///         SCOPE: proves the CONDITIONAL deny branch only (isModuleType-succeeds => revert). The
///         heuristic's soundness against adversarial bytecode that REVERTS isModuleType (bypass) is
///         SG-B, not FV-decidable, and NOT claimed here.
contract DefaultSecurityHookDenyModuleHalmos is SymTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    DefaultSecurityHook internal hook;

    // Distinct concrete addresses for account (msg.sender) and target so target != msg.sender is
    // structurally guaranteed. TARGET gets a SUCCEED-stub etched inline (returns 32 zero bytes for
    // any calldata) so its isModuleType staticcall returns success==true => _isModule(TARGET)==true.
    // Source :208-212 only checks staticcall success, not return data, so a trivial returner is a
    // faithful "module-like" target; value and selector stay fully symbolic.
    address internal constant ACCOUNT = address(uint160(uint256(keccak256("module.account"))));
    address internal constant TARGET = address(uint160(uint256(keccak256("module.target"))));

    function setUp() external {
        hook = DefaultSecurityHook(address(uint160(uint256(keccak256("DefaultSecurityHook")))));
        vm.etch(address(hook), type(DefaultSecurityHook).runtimeCode);
    }

    /// @dev Etch a SUCCEED stub (PUSH1 0x20 PUSH1 0x00 RETURN — returns 32 zero bytes) at TARGET so
    ///      target.staticcall(isModuleType, 0) returns success==true => _isModule(TARGET)==true.
    ///      Well under the 30k stipend (:210).
    function _makeTargetModule() internal {
        vm.etch(TARGET, hex"60206000f3");
    }

    /// @dev Build preCheck msgData for a CALLTYPE_SINGLE call (mode high byte 0x00),
    ///      packed executionData = target(20) || value(32) || selector(4). Length 0x38 > 0x33 so
    ///      LibERC7579.decodeSingle succeeds.
    function _buildSingleMsgData(address target, uint256 value, bytes4 selector)
        internal
        view
        returns (bytes memory msgData)
    {
        bytes32 mode = bytes32(0); // high byte == 0x00 => CALLTYPE_SINGLE
        bytes memory executionData = abi.encodePacked(target, value, selector);
        // preCheck reads the inner `msgData` param as: [0:4] dummy selector, [4:36] mode,
        // [36:68] ABI offset for the executionData bytes, then length + data.
        bytes memory param = abi.encodePacked(bytes4(0), abi.encode(mode, executionData));
        msgData = abi.encodeWithSelector(hook.preCheck.selector, address(0), uint256(0), param);
    }

    /// @notice OBSERVABLE: for a SINGLE call to a non-allowlisted, non-self target whose
    ///         isModuleType(0) staticcall succeeds, preCheck reverts with exactly
    ///         ModuleCallNotAllowed(target) for ALL symbolic (value, selector). Source :196.
    ///         Exact revert-data equality over the full symbolic region (value includes 0 and >0;
    ///         selector includes the blocked token set) simultaneously pins the check order: any
    ///         input where ETHTransferNotAllowed or TokenTransferNotAllowed fired instead would be
    ///         a counterexample. No branch logic is reimplemented here — only the observed revert
    ///         data is asserted.
    function check_DenyModuleCall() external {
        _makeTargetModule();

        // Installed but NO allowlist entry for TARGET => entry.allowed==false, so the
        // allowlist-first branch (:187-190) cannot return regardless of the symbolic selector.
        vm.prank(ACCOUNT);
        hook.onInstall("");

        uint256 value = svm.createUint256("value");
        bytes4 selector = svm.createBytes4("selector");

        bytes memory msgData = _buildSingleMsgData(TARGET, value, selector);

        vm.prank(ACCOUNT);
        (bool ok, bytes memory ret) = address(hook).call(msgData);

        assert(!ok);
        assert(
            keccak256(ret)
                == keccak256(abi.encodeWithSelector(DefaultSecurityHook.ModuleCallNotAllowed.selector, TARGET))
        );
    }

    /// @notice Reachability/vacuity witness for check_DenyModuleCall: guards on the exact
    ///         ModuleCallNotAllowed leaf under the SAME preconditions (installed account +
    ///         succeeding-stub target, no assumes) and asserts false, so Halmos MUST emit a
    ///         counterexample proving the leaf is live and that an initialized account and a
    ///         succeeding-stub target coexist. NO counterexample => leaf dead / setup vacuous.
    function check_DenyModuleCall_reachable() external {
        _makeTargetModule();

        vm.prank(ACCOUNT);
        hook.onInstall("");

        uint256 value = svm.createUint256("value");
        bytes4 selector = svm.createBytes4("selector");

        bytes memory msgData = _buildSingleMsgData(TARGET, value, selector);

        vm.prank(ACCOUNT);
        (bool ok, bytes memory ret) = address(hook).call(msgData);

        if (
            !ok
                && keccak256(ret)
                    == keccak256(abi.encodeWithSelector(DefaultSecurityHook.ModuleCallNotAllowed.selector, TARGET))
        ) {
            assert(false);
        }
    }
}
