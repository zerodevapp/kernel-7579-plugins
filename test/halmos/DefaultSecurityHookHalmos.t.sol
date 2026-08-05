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
/// @notice Halmos proof harness for DefaultSecurityHook access control (req-14) and the
///         delegatecall guard. Deploys via etch because Halmos 0.3.3 cannot execute the
///         via_ir creation bytecode (routes to an unsupported deployCode(string) cheat);
///         DefaultSecurityHook has no constructor logic (all state via onInstall), so etch
///         is state-equivalent.
contract DefaultSecurityHookHalmos is SymTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    DefaultSecurityHook internal hook;

    function setUp() external {
        hook = DefaultSecurityHook(address(uint160(uint256(keccak256("DefaultSecurityHook")))));
        vm.etch(address(hook), type(DefaultSecurityHook).runtimeCode);
    }

    // ==================================================================================
    // Delegatecall guard: preCheck always reverts DelegateCallNotAllowed for callType 0xff.
    // ==================================================================================

    /// @notice preCheck ALWAYS reverts DelegateCallNotAllowed when the mode's callType byte
    ///         (bytes1(mode) == 0xff, CALLTYPE_DELEGATECALL), regardless of executionData,
    ///         allowlist state, or account — the delegatecall branch runs before the allowlist
    ///         branch, so allowlisting cannot bypass it.
    function check_DelegateCallAlwaysReverts() external {
        bytes memory executionData = svm.createBytes(64, "executionData");
        // mode is a 32-byte word; its high byte (bytes1(mode)) is the callType. Force it to 0xff
        // (CALLTYPE_DELEGATECALL); the remaining mode bits are left symbolic.
        uint256 modeTail = svm.createUint(248, "modeTail"); // low 31 bytes, symbolic
        bytes32 mode = bytes32((uint256(0xff) << 248) | modeTail);

        // "Even fully allowlisted": install the account and allow-all a symbolic target.
        address account = svm.createAddress("account");
        address target = svm.createAddress("target");
        vm.prank(account);
        hook.onInstall("");
        vm.prank(account);
        hook.setAllowlist(target, new bytes4[](0)); // empty => allSelectorsAllowed

        // preCheck's `msgData` param layout is [0:4] execute selector, [4:36] mode, [36:] data.
        // getCallType reads bytes1(msgData[4:36]) == param byte[4]. The param MUST therefore start
        // with a 4-byte (dummy) selector so `mode` lands at [4:36] and its high byte (0xff) is byte[4].
        bytes memory param = abi.encodePacked(bytes4(0), mode, executionData);
        bytes memory msgData = abi.encodeWithSelector(hook.preCheck.selector, address(0), uint256(0), param);

        vm.prank(account);
        (bool ok, bytes memory ret) = address(hook).call(msgData);
        assert(!ok);
        assert(bytes4(ret) == DefaultSecurityHook.DelegateCallNotAllowed.selector);
    }

    /// @notice Reachability/vacuity witness for check_DelegateCallAlwaysReverts: proves the
    ///         precondition set (well-formed param with callType byte==0xff, installed + allowlisted
    ///         account) is satisfiable AND the DelegateCallNotAllowed revert path is actually
    ///         reached (not blocked by an earlier calldata-decode revert). Guards on the intended
    ///         revert leaf then asserts false, so Halmos MUST emit a counterexample; NO counterexample
    ///         => preconditions unsatisfiable / path dead (VACUOUS).
    function check_DelegateCallAlwaysReverts_reachable() external {
        bytes memory executionData = svm.createBytes(64, "executionData");
        uint256 modeTail = svm.createUint(248, "modeTail");
        bytes32 mode = bytes32((uint256(0xff) << 248) | modeTail);

        address account = svm.createAddress("account");
        address target = svm.createAddress("target");
        vm.prank(account);
        hook.onInstall("");
        vm.prank(account);
        hook.setAllowlist(target, new bytes4[](0));

        bytes memory param = abi.encodePacked(bytes4(0), mode, executionData);
        bytes memory msgData = abi.encodeWithSelector(hook.preCheck.selector, address(0), uint256(0), param);

        vm.prank(account);
        (bool ok, bytes memory ret) = address(hook).call(msgData);

        // Only proceed on the intended live revert leaf; assert false to force a counterexample.
        if (!ok && bytes4(ret) == DefaultSecurityHook.DelegateCallNotAllowed.selector) {
            assert(false);
        }
    }

    // ==================================================================================
    // req-14: allowlist-write access control (uninitialized caller cannot write).
    // ==================================================================================

    /// @notice req-14 (OBSERVABLE): setAllowlist reverts Unauthorized when msg.sender is
    ///         UNINITIALIZED (initialized[caller]==false). Source guard:
    ///         DefaultSecurityHook.sol:154 `if (!initialized[msg.sender]) revert Unauthorized();`.
    ///         Asserts the revert selector, not a recompute of the init flag (non-tautological).
    function check_SetAllowlistRevertsWhenUninitialized() external {
        address caller = svm.createAddress("caller");
        address target = svm.createAddress("target");

        // Genuine spec precondition: a fresh account defaults to initialized==false.
        vm.assume(!hook.isInitialized(caller));

        bytes4[] memory sels = new bytes4[](1);
        sels[0] = svm.createBytes4("selector");

        vm.prank(caller);
        (bool ok, bytes memory ret) = address(hook).call(abi.encodeCall(hook.setAllowlist, (target, sels)));

        // OBSERVABLE postcondition: the call reverts with exactly Unauthorized().
        assert(!ok);
        assert(bytes4(ret) == DefaultSecurityHook.Unauthorized.selector);
    }

    /// @notice Reachability witness for req-14: proves an INITIALIZED caller CAN successfully
    ///         setAllowlist (the revert is a genuine guard, not universal) AND the uninitialized
    ///         precondition is satisfiable. Asserts false on the success leaf so Halmos MUST emit
    ///         a counterexample; no CEX => path dead / precondition vacuous.
    function check_SetAllowlistRevertsWhenUninitialized_reachable() external {
        address caller = svm.createAddress("caller");
        address target = svm.createAddress("target");

        // Same uninitialized precondition must be satisfiable...
        vm.assume(!hook.isInitialized(caller));

        // ...and an initialized caller CAN write. onInstall flips initialized[caller]=true.
        vm.prank(caller);
        hook.onInstall("");

        bytes4[] memory sels = new bytes4[](1);
        sels[0] = svm.createBytes4("selector");

        vm.prank(caller);
        (bool ok,) = address(hook).call(abi.encodeCall(hook.setAllowlist, (target, sels)));

        // ok==true means the write succeeded => guard is a genuine, live gate.
        // Assert false on the success leaf so a counterexample witnesses reachability.
        assert(!ok);
    }

    // ==================================================================================
    // Lifecycle: onInstall -> onUninstall roundtrip returns isInitialized to false.
    // ==================================================================================

    /// @notice Init lifecycle (OBSERVABLE): starting from a symbolic (fresh)
    ///         account, an onInstall followed by onUninstall returns isInitialized(account)
    ///         to false. Source: onInstall :80 sets initialized=true, onUninstall :102 sets
    ///         it back to false. onInstall data kept empty (data.length==0 branch, :82) so
    ///         the AllowlistConfig decode loop is skipped — the flag roundtrip is independent
    ///         of config parsing. Asserts the observable isInitialized() view, not the raw slot.
    function check_InstallUninstallRoundtrip() external {
        address account = svm.createAddress("account");

        // Genuine spec precondition: a fresh account defaults to initialized==false.
        vm.assume(!hook.isInitialized(account));

        vm.prank(account);
        hook.onInstall("");

        vm.prank(account);
        hook.onUninstall("");

        // OBSERVABLE postcondition: the roundtrip leaves the account un-initialized.
        assert(!hook.isInitialized(account));
    }

    /// @notice Reachability/vacuity witness for check_InstallUninstallRoundtrip: proves the
    ///         fresh-account precondition is satisfiable AND that both the onInstall success
    ///         path (initialized false -> true) and the onUninstall success path are actually
    ///         taken (neither reverts). Asserts isInitialized(account)==true immediately after
    ///         onInstall (before onUninstall) on the live path, then asserts false so Halmos
    ///         MUST emit a counterexample. No CEX => a path reverted / precondition unsatisfiable
    ///         (VACUOUS).
    function check_InstallUninstallRoundtrip_reachable() external {
        address account = svm.createAddress("account");

        vm.assume(!hook.isInitialized(account));

        vm.prank(account);
        hook.onInstall("");

        // Success path of onInstall was taken: flag flipped to true.
        if (hook.isInitialized(account)) {
            vm.prank(account);
            hook.onUninstall("");
            // Both success paths live; force a counterexample to witness reachability.
            assert(false);
        }
    }

    // ==================================================================================
    // Self-call gate: preCheck reverts SelfCallNotAllowed for a SINGLE call whose decoded
    // target == the account (msg.sender), when that (self,selector) pair is NOT allowlisted.
    // ==================================================================================

    /// @notice preCheck reverts SelfCallNotAllowed when the SINGLE-call decoded target equals the
    ///         account (msg.sender) and self is NOT allowlisted for the call. Source:
    ///         DefaultSecurityHook.sol:193 `if (target == msg.sender) revert SelfCallNotAllowed()`,
    ///         reached because the allowlist-first branch (:187-190) does not return for a
    ///         non-allowlisted entry. Asserts the specific revert selector (non-tautological): a
    ///         different revert (e.g. UnsupportedCallType, DecodingError) would be a false pass.
    function check_DenySelfCall() external {
        // Symbolic value and 4-byte data so the gate holds for any selector/value.
        uint256 value = svm.createUint256("value");
        bytes4 selector = svm.createBytes4("selector");

        address account = svm.createAddress("account");
        vm.prank(account);
        hook.onInstall("");
        // NOT allowlisted: no setAllowlist call => allowlist[account][account].allowed == false,
        // so the allowlist-first branch is skipped and control reaches the self-call gate.

        // executionData for a single call: abi.encodePacked(target(20), value(32), data).
        // target == account == msg.sender pins the self-call precondition.
        bytes memory executionData = abi.encodePacked(account, value, selector);

        // mode with callType byte == 0x00 (CALLTYPE_SINGLE); remaining bytes symbolic.
        uint256 modeTail = svm.createUint(248, "modeTail");
        bytes32 mode = bytes32(modeTail); // high byte (callType) == 0x00 = SINGLE

        // preCheck reads msgData as [0:4] dummy selector, then ABI-encoded (bytes32 mode, bytes
        // executionData) at [4:]; it resolves executionData via the ABI offset word at [36:68], so
        // for the SINGLE branch (which dereferences executionData) it MUST be ABI-encoded
        // (offset+length+data), NOT packed (unlike the delegatecall harness which never reads it).
        bytes memory param = abi.encodePacked(bytes4(0), abi.encode(mode, executionData));
        bytes memory msgData = abi.encodeWithSelector(hook.preCheck.selector, address(0), uint256(0), param);

        vm.prank(account);
        (bool ok, bytes memory ret) = address(hook).call(msgData);

        assert(!ok);
        assert(bytes4(ret) == DefaultSecurityHook.SelfCallNotAllowed.selector);
    }

    /// @notice Reachability/vacuity witness for check_DenySelfCall: guards the intended
    ///         SelfCallNotAllowed revert leaf (SINGLE mode, target==self, not allowlisted) then
    ///         asserts false, so Halmos MUST emit a counterexample. NO counterexample => the leaf
    ///         is dead / preconditions unsatisfiable (VACUOUS, report as such — not proven).
    function check_DenySelfCall_reachable() external {
        uint256 value = svm.createUint256("value");
        bytes4 selector = svm.createBytes4("selector");

        address account = svm.createAddress("account");
        vm.prank(account);
        hook.onInstall("");

        bytes memory executionData = abi.encodePacked(account, value, selector);

        uint256 modeTail = svm.createUint(248, "modeTail");
        bytes32 mode = bytes32(modeTail);

        bytes memory param = abi.encodePacked(bytes4(0), abi.encode(mode, executionData));
        bytes memory msgData = abi.encodeWithSelector(hook.preCheck.selector, address(0), uint256(0), param);

        vm.prank(account);
        (bool ok, bytes memory ret) = address(hook).call(msgData);

        // Only proceed on the intended live revert leaf; assert false to force a counterexample.
        if (!ok && bytes4(ret) == DefaultSecurityHook.SelfCallNotAllowed.selector) {
            assert(false);
        }
    }

    // ==================================================================================
    // Unsupported callType dispatch: preCheck reverts UnsupportedCallType for ANY callType
    // that is not SINGLE (0x00), BATCH (0x01), or DELEGATECALL (0xff). Source: :112-147,
    // else-branch revert at :143.
    // ==================================================================================

    /// @notice preCheck reverts EXACTLY UnsupportedCallType() when the mode's callType byte
    ///         (bytes1(mode), read by LibERC7579.getCallType) is NONE of CALLTYPE_SINGLE (0x00),
    ///         CALLTYPE_BATCH (0x01), or CALLTYPE_DELEGATECALL (0xff). The excluded set forces the
    ///         else-branch at :143 to be the only reachable leaf; asserting the specific
    ///         UnsupportedCallType selector (not delegatecall's revert) keeps this non-tautological.
    function check_UnsupportedCallTypeReverts() external {
        bytes memory executionData = svm.createBytes(64, "executionData");
        // callType is the HIGH byte of the 32-byte mode word (bytes1(mode)). Make it symbolic and
        // exclude the three handled types so only the else-branch (:143) can be reached.
        uint256 callTypeByte = svm.createUint(8, "callTypeByte");
        vm.assume(callTypeByte != 0x00); // != CALLTYPE_SINGLE
        vm.assume(callTypeByte != 0x01); // != CALLTYPE_BATCH
        vm.assume(callTypeByte != 0xff); // != CALLTYPE_DELEGATECALL
        uint256 modeTail = svm.createUint(248, "modeTail"); // low 31 bytes symbolic
        bytes32 mode = bytes32((callTypeByte << 248) | modeTail);

        // Even for an installed + fully-allowlisted account, dispatch happens before allowlist logic.
        address account = svm.createAddress("account");
        address target = svm.createAddress("target");
        vm.prank(account);
        hook.onInstall("");
        vm.prank(account);
        hook.setAllowlist(target, new bytes4[](0));

        // preCheck reads msgData[4:] as ABI-encoded (bytes32 mode, bytes executionData): the
        // executionData OFFSET word at msgData[36:68] must be the concrete 0x40, so use abi.encode
        // (NOT abi.encodePacked) for the (mode, executionData) tail — the assembly at :126-131
        // runs BEFORE the else at :143 and dereferences that offset, needing it concrete.
        bytes memory param = abi.encodePacked(bytes4(0), abi.encode(mode, executionData));
        bytes memory msgData = abi.encodeWithSelector(hook.preCheck.selector, address(0), uint256(0), param);

        vm.prank(account);
        (bool ok, bytes memory ret) = address(hook).call(msgData);

        // OBSERVABLE: reverts with EXACTLY UnsupportedCallType (the :143 leaf, not delegatecall's).
        assert(!ok);
        assert(bytes4(ret) == DefaultSecurityHook.UnsupportedCallType.selector);
    }

    /// @notice Reachability/vacuity witness for check_UnsupportedCallTypeReverts: proves at least
    ///         one non-{single,batch,delegatecall} callType value exists and actually reaches the
    ///         UnsupportedCallType leaf (not blocked by an earlier decode revert). Guards on the
    ///         intended leaf then asserts false so Halmos MUST emit a counterexample; no CEX =>
    ///         excluded set empty / else-branch dead (VACUOUS).
    function check_UnsupportedCallTypeReverts_reachable() external {
        bytes memory executionData = svm.createBytes(64, "executionData");
        uint256 callTypeByte = svm.createUint(8, "callTypeByte");
        vm.assume(callTypeByte != 0x00);
        vm.assume(callTypeByte != 0x01);
        vm.assume(callTypeByte != 0xff);
        uint256 modeTail = svm.createUint(248, "modeTail");
        bytes32 mode = bytes32((callTypeByte << 248) | modeTail);

        address account = svm.createAddress("account");
        address target = svm.createAddress("target");
        vm.prank(account);
        hook.onInstall("");
        vm.prank(account);
        hook.setAllowlist(target, new bytes4[](0));

        // abi.encode (not packed): concrete executionData offset word for the :126-131 assembly.
        bytes memory param = abi.encodePacked(bytes4(0), abi.encode(mode, executionData));
        bytes memory msgData = abi.encodeWithSelector(hook.preCheck.selector, address(0), uint256(0), param);

        vm.prank(account);
        (bool ok, bytes memory ret) = address(hook).call(msgData);

        // Only the intended live revert leaf reaches assert(false) => forces a counterexample.
        if (!ok && bytes4(ret) == DefaultSecurityHook.UnsupportedCallType.selector) {
            assert(false);
        }
    }
}
