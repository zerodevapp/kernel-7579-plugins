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
/// @notice Halmos proof harness for removeAllowlist correctness (spec §5.3) — the uncovered
///         half of allowlist management. Own file/contract (etch-deploy pattern identical to
///         DefaultSecurityHookHalmos; state-equivalent, no constructor logic).
///
///         (a) ACCESS: removeAllowlist(target) reverts Unauthorized() when
///             initialized[msg.sender]==false (src:160), mirroring the proven setAllowlist gate.
///         (b) DENY RESTORED: after a real setAllowlist(target, selectors) (symbolic list,
///             length<=2, incl. the empty/blanket case) followed by removeAllowlist(target),
///             the allowlist is observably gone — isAllowlisted==false, isSelectorAllowed==false
///             for a symbolic selector — and a _checkCall-routed SINGLE call to target with
///             value>0 (symbolic selector, incl. the pre-remove-allowlisted one) reverts
///             ETHTransferNotAllowed again, i.e. no stale allowed/allSelectorsAllowed/selectors
///             bit survives _clearAllowlist (src:248-260). Asserted exclusively via public views
///             and observable reverts (no internal-slot reads => non-tautological).
contract DefaultSecurityHookRemoveAllowlistHalmos is SymTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    DefaultSecurityHook internal hook;

    // Distinct concrete addresses so target != msg.sender is structural. TARGET gets a REVERT
    // stub etched so its isModuleType staticcall fails => _isModule(TARGET)==false (non-module).
    address internal constant ACCOUNT = address(uint160(uint256(keccak256("remove.account"))));
    address internal constant TARGET = address(uint160(uint256(keccak256("remove.target"))));

    function setUp() external {
        hook = DefaultSecurityHook(address(uint160(uint256(keccak256("DefaultSecurityHook")))));
        vm.etch(address(hook), type(DefaultSecurityHook).runtimeCode);
        // REVERT stub (PUSH1 0 PUSH1 0 REVERT): staticcall success==false => not a module.
        vm.etch(TARGET, hex"60006000fd");
    }

    // ==================================================================================
    // (a) ACCESS: removeAllowlist reverts Unauthorized for an uninitialized caller.
    // ==================================================================================

    /// @notice OBSERVABLE: removeAllowlist(target) reverts with exactly Unauthorized() when
    ///         initialized[msg.sender]==false. Source: DefaultSecurityHook.sol:160
    ///         `if (!initialized[msg.sender]) revert Unauthorized();`. Mirror of the proven
    ///         setAllowlist gate (DSH-ACCESS-01); asserts the revert selector, not a recompute
    ///         of the init flag.
    function check_RemoveAllowlistRevertsWhenUninitialized() external {
        address caller = svm.createAddress("caller");
        address target = svm.createAddress("target");

        // Genuine spec precondition: a fresh account defaults to initialized==false.
        vm.assume(!hook.isInitialized(caller));

        vm.prank(caller);
        (bool ok, bytes memory ret) = address(hook).call(abi.encodeCall(hook.removeAllowlist, (target)));

        assert(!ok);
        assert(bytes4(ret) == DefaultSecurityHook.Unauthorized.selector);
    }

    /// @notice Reachability/vacuity witness for (a): the uninitialized precondition is
    ///         satisfiable AND an INITIALIZED caller CAN successfully removeAllowlist (the
    ///         revert is a genuine gate, not universal). Asserts false on the success leaf so
    ///         Halmos MUST emit a counterexample; no CEX => path dead / precondition vacuous.
    function check_RemoveAllowlistRevertsWhenUninitialized_reachable() external {
        address caller = svm.createAddress("caller");
        address target = svm.createAddress("target");

        // Same uninitialized precondition must be satisfiable...
        vm.assume(!hook.isInitialized(caller));

        // ...and an initialized caller CAN remove. onInstall flips initialized[caller]=true.
        vm.prank(caller);
        hook.onInstall("");

        vm.prank(caller);
        (bool ok,) = address(hook).call(abi.encodeCall(hook.removeAllowlist, (target)));

        // ok==true means the remove succeeded => guard is a genuine, live gate.
        assert(!ok);
    }

    // ==================================================================================
    // (b) DENY RESTORED: setAllowlist then removeAllowlist leaves no observable allow bit.
    // ==================================================================================

    /// @dev Build a symbolic selector list of symbolic length n <= 2 (n==0 is the empty/blanket
    ///      allSelectorsAllowed case) and return it with s0 (first element when n>=1).
    ///      Explicit if/else fork per length so each Halmos path has a CONCRETE array length
    ///      (a symbolic `new bytes4[](n)` hits NotConcreteError: symbolic CALLDATACOPY size);
    ///      all three lengths are still covered, as separate symbolic paths.
    function _symbolicSelectors() internal returns (bytes4[] memory sels, bytes4 s0) {
        uint256 n = svm.createUint(2, "n"); // 2-bit symbolic: 0..3
        vm.assume(n <= 2);
        s0 = svm.createBytes4("s0");
        if (n == 0) {
            sels = new bytes4[](0); // blanket: allSelectorsAllowed
        } else if (n == 1) {
            sels = new bytes4[](1);
            sels[0] = s0;
        } else {
            sels = new bytes4[](2);
            sels[0] = s0;
            sels[1] = svm.createBytes4("s1");
        }
    }

    /// @dev preCheck msgData for CALLTYPE_SINGLE (mode high byte 0x00), packed executionData =
    ///      target(20) || value(32) || selector(4); param = dummySelector || abi.encode(mode, ed).
    function _buildSingleMsgData(address target, uint256 value, bytes4 selector)
        internal
        view
        returns (bytes memory msgData)
    {
        bytes32 mode = bytes32(0); // CALLTYPE_SINGLE
        bytes memory executionData = abi.encodePacked(target, value, selector);
        bytes memory param = abi.encodePacked(bytes4(0), abi.encode(mode, executionData));
        msgData = abi.encodeWithSelector(hook.preCheck.selector, address(0), uint256(0), param);
    }

    /// @dev Shared (b) pipeline: onInstall -> setAllowlist(TARGET, symbolic sels) ->
    ///      removeAllowlist(TARGET) -> follow-up preCheck with value>0 and the pre-remove
    ///      allowed selector (s0 when n>=1, fully symbolic when n==0/blanket). Returns the
    ///      observable pin (allowed-after-set), the follow-up call result, and the query
    ///      selector inputs so both the main check and the reachability companion use the
    ///      IDENTICAL precondition set.
    function _setThenRemove() internal returns (bool allowedAfterSet, bool ok, bytes memory ret, uint256 value) {
        (bytes4[] memory sels, bytes4 s0) = _symbolicSelectors();

        vm.prank(ACCOUNT);
        hook.onInstall("");
        vm.prank(ACCOUNT);
        hook.setAllowlist(TARGET, sels);

        // Observable pin: the pre-remove state really is allowlisted.
        allowedAfterSet = hook.isAllowlisted(ACCOUNT, TARGET);
        vm.assume(allowedAfterSet);

        vm.prank(ACCOUNT);
        hook.removeAllowlist(TARGET);

        // Follow-up _checkCall-routed call: value>0, selector = the one that WAS allowed
        // pre-remove (s0 when the list is non-empty; any symbolic selector in the blanket case).
        value = svm.createUint256("value");
        vm.assume(value > 0);
        bytes4 callSel = sels.length == 0 ? svm.createBytes4("anySel") : s0;
        bytes memory msgData = _buildSingleMsgData(TARGET, value, callSel);

        vm.prank(ACCOUNT);
        (ok, ret) = address(hook).call(msgData);
    }

    /// @notice OBSERVABLE (spec §5.3 DENY RESTORED): for an initialized ACCOUNT that ran a real
    ///         setAllowlist(TARGET, selectors) (symbolic list, length<=2, incl. empty/blanket)
    ///         and was observably allowlisted, after removeAllowlist(TARGET):
    ///         isAllowlisted==false, isSelectorAllowed==false for a symbolic selector, and the
    ///         follow-up SINGLE preCheck to TARGET with value>0 and the previously-allowed
    ///         selector reverts with exactly ETHTransferNotAllowed(TARGET, value) — no stale
    ///         allowed/allSelectorsAllowed/selectors[s] bit survives _clearAllowlist (:248-260).
    ///         All three legs are the ONE dispatched postcondition conjunction; asserted via
    ///         public views + the observable revert only.
    function check_RemoveAllowlistRestoresDeny() external {
        (, bool ok, bytes memory ret, uint256 value) = _setThenRemove();

        // View leg 1: entry no longer allowlisted.
        assert(!hook.isAllowlisted(ACCOUNT, TARGET));
        // View leg 2: no selector (symbolic, incl. the ones just set) is allowed.
        bytes4 sQ = svm.createBytes4("sQ");
        assert(!hook.isSelectorAllowed(ACCOUNT, TARGET, sQ));
        // Revert leg: the follow-up call is denied again with the exact ETH-gate error (:199),
        // proving the allowlist-first branch (:187-190) no longer returns early.
        assert(!ok);
        assert(
            keccak256(ret)
                == keccak256(abi.encodeWithSelector(DefaultSecurityHook.ETHTransferNotAllowed.selector, TARGET, value))
        );
    }

    /// @notice Reachability/vacuity witness for (b), SAME precondition pipeline: proves
    ///         (i) the setAllowlist=>isAllowlisted==true pre-state pin is satisfiable and
    ///         (ii) the post-remove ETHTransferNotAllowed deny leaf is actually reached (not
    ///         shadowed by SelfCall/ModuleCall/decode reverts). Guards on the intended leaf
    ///         then asserts false, so Halmos MUST emit a counterexample; NO counterexample =>
    ///         preconditions unsatisfiable or leaf dead (VACUOUS — report as such, not proven).
    function check_RemoveAllowlistRestoresDeny_reachable() external {
        (bool allowedAfterSet, bool ok, bytes memory ret, uint256 value) = _setThenRemove();

        if (
            allowedAfterSet && !ok
                && keccak256(ret)
                    == keccak256(
                        abi.encodeWithSelector(DefaultSecurityHook.ETHTransferNotAllowed.selector, TARGET, value)
                    )
        ) {
            assert(false);
        }
    }
}
