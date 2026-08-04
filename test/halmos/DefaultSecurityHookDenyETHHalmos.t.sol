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
/// @notice Halmos proof harness for the DefaultSecurityHook ETH-transfer gate (_checkCall :199).
///         Split into its own file/contract (rather than DefaultSecurityHookHalmos) to avoid a
///         concurrent-edit race; the etch-deploy pattern is identical and state-equivalent
///         (DefaultSecurityHook has no constructor logic, all state via onInstall).
///
///         Property: for a SINGLE call with value>0 to a target that is NOT allowlisted, NOT the
///         caller (target != msg.sender), and NOT a module (_isModule(target)==false), preCheck
///         reverts ETHTransferNotAllowed(target, value). The ETH check sits AFTER the module check
///         (:196), so the reachability witness MUST show _isModule can return false, else the
///         revert would be shadowed by ModuleCallNotAllowed.
contract DefaultSecurityHookDenyETHHalmos is SymTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    DefaultSecurityHook internal hook;

    // Distinct concrete addresses for account (msg.sender) and target so target != msg.sender is
    // structurally guaranteed. TARGET gets a revert-stub etched inline so its isModuleType
    // staticcall returns success==false => _isModule(TARGET)==false. This is the
    // uninterpreted-staticcall model for this reachable leaf: the external call outcome is fixed to
    // "not a module" while `value` and the call selector stay fully symbolic.
    address internal constant ACCOUNT = address(uint160(uint256(keccak256("eth.account"))));
    address internal constant TARGET = address(uint160(uint256(keccak256("eth.target"))));

    // Additional revert-stub targets for the symbolic-target generalization (SG-P3-1). Three
    // distinct addresses with etched REVERT stubs; a symbolic target address is then constrained
    // only by the OBSERVABLE precondition "the isModuleType staticcall fails" (ghost pre-flight),
    // so Halmos's address resolution — not a hand-pinned constant — picks the satisfying targets.
    address internal constant STUB_A = address(uint160(uint256(keccak256("eth.target.stubA"))));
    address internal constant STUB_B = address(uint160(uint256(keccak256("eth.target.stubB"))));
    address internal constant STUB_C = address(uint160(uint256(keccak256("eth.target.stubC"))));

    bytes4 internal constant IS_MODULE_TYPE = bytes4(keccak256("isModuleType(uint256)"));

    function setUp() external {
        hook = DefaultSecurityHook(address(uint160(uint256(keccak256("DefaultSecurityHook")))));
        vm.etch(address(hook), type(DefaultSecurityHook).runtimeCode);
    }

    /// @dev Etch a REVERT stub (PUSH1 0 PUSH1 0 REVERT) at TARGET so
    ///      target.staticcall(isModuleType,...) returns success==false => _isModule(TARGET)==false.
    function _makeTargetNotModule() internal {
        vm.etch(TARGET, hex"60006000fd");
    }

    /// @dev Build preCheck msgData for a CALLTYPE_SINGLE call (mode high byte 0x00, tail symbolic),
    ///      packed executionData = target(20) || value(32) || selector(4). Length 0x38 > 0x33 so
    ///      LibERC7579.decodeSingle succeeds.
    function _buildSingleMsgData(address target, uint256 value) internal returns (bytes memory msgData) {
        bytes32 mode = bytes32(0); // high byte == 0x00 => CALLTYPE_SINGLE
        bytes4 selector = svm.createBytes4("selector");
        bytes memory executionData = abi.encodePacked(target, value, selector);
        // preCheck reads the inner `msgData` param as: [0:4] dummy selector, [4:36] mode,
        // [36:68] ABI offset for the executionData bytes, then length + data. So the param must be
        // dummy-selector || abi.encode(mode, executionData) (proper ABI framing for the inner bytes).
        bytes memory param = abi.encodePacked(bytes4(0), abi.encode(mode, executionData));
        msgData = abi.encodeWithSelector(hook.preCheck.selector, address(0), uint256(0), param);
    }

    /// @notice OBSERVABLE: for a SINGLE call with value>0 to a target that is NOT allowlisted, NOT
    ///         the caller, and NOT a module, preCheck reverts with exactly
    ///         ETHTransferNotAllowed(target, value) — full ABI-encoded args matching the decoded
    ///         (target, value). Source: DefaultSecurityHook.sol:199. Asserts the specific selector
    ///         AND the encoded args over the full symbolic value>0 region (not a fixed constant),
    ///         so a different revert (ModuleCallNotAllowed, DecodingError) is a false pass.
    function check_DenyETH() external {
        _makeTargetNotModule();

        // Installed but NO allowlist entry for TARGET => entry.allowed==false, so the allowlist-first
        // branch (:187-190) cannot return regardless of the (symbolic) selector.
        vm.prank(ACCOUNT);
        hook.onInstall("");

        uint256 value = svm.createUint256("value");
        vm.assume(value > 0); // ETH-transfer region, symbolic (covers all value>0)

        bytes memory msgData = _buildSingleMsgData(TARGET, value);

        vm.prank(ACCOUNT);
        (bool ok, bytes memory ret) = address(hook).call(msgData);

        assert(!ok);
        assert(
            keccak256(ret)
                == keccak256(abi.encodeWithSelector(DefaultSecurityHook.ETHTransferNotAllowed.selector, TARGET, value))
        );
    }

    /// @notice Reachability/vacuity witness for check_DenyETH: proves the value>0 /
    ///         not-allowlisted / not-self / not-module leg is LIVE. It depends on
    ///         _isModule(TARGET)==false: because the ETH check (:199) sits AFTER the module check
    ///         (:196), if the staticcall could not return success==false this revert would be
    ///         shadowed by ModuleCallNotAllowed and the leaf would be dead. Guards on the exact
    ///         ETHTransferNotAllowed leaf then asserts false, so Halmos MUST emit a counterexample;
    ///         NO counterexample => leaf dead / preconditions vacuous.
    function check_DenyETH_reachable() external {
        _makeTargetNotModule();

        vm.prank(ACCOUNT);
        hook.onInstall("");

        uint256 value = svm.createUint256("value");
        vm.assume(value > 0);

        bytes memory msgData = _buildSingleMsgData(TARGET, value);

        vm.prank(ACCOUNT);
        (bool ok, bytes memory ret) = address(hook).call(msgData);

        if (
            !ok
                && keccak256(ret)
                    == keccak256(
                        abi.encodeWithSelector(DefaultSecurityHook.ETHTransferNotAllowed.selector, TARGET, value)
                    )
        ) {
            assert(false);
        }
    }

    /// @dev Shared body for the symbolic-target property and its reachability companion: etch
    ///      REVERT stubs at three distinct addresses, install for ACCOUNT with NO allowlist, create
    ///      a SYMBOLIC target, and encode the preconditions observably:
    ///        - target != ACCOUNT (not-self)
    ///        - isAllowlisted(ACCOUNT, target) == false (observable view, holds via empty allowlist
    ///          storage for ALL targets — asserted through the contract's own view, not assumed
    ///          away by pinning a constant)
    ///        - _isModule(target) == false, expressed as a ghost pre-flight of the SAME staticcall
    ///          the hook performs (:208-212) with vm.assume(!success). Within any single path,
    ///          Halmos resolves the symbolic callee consistently, so the hook's own staticcall in
    ///          _checkCall agrees with the pre-flight. Targets resolving to codeless addresses or
    ///          to live isModuleType responders (e.g. the hook itself) have success==true and are
    ///          excluded — correctly, because for them the real contract reverts
    ///          ModuleCallNotAllowed BEFORE the ETH check and the stated precondition is false.
    ///      COVERAGE DISCLOSURE: Halmos 0.3.3 resolves symbolic call targets against deployed code;
    ///      the satisfying set here is the three etched stubs (plus any resolution Halmos adds).
    ///      The target ADDRESS is symbolic, but "has code whose isModuleType call reverts" is
    ///      modeled by these stubs — targets whose staticcall fails for other reasons (e.g. >30k
    ///      gas burn) share the same success==false observable and the same _checkCall branch.
    function _denyETHSymbolicTarget() internal returns (address target, uint256 value, bool ok, bytes memory ret) {
        vm.etch(STUB_A, hex"60006000fd");
        vm.etch(STUB_B, hex"60006000fd");
        vm.etch(STUB_C, hex"60006000fd");

        vm.prank(ACCOUNT);
        hook.onInstall("");

        target = svm.createAddress("target");
        vm.assume(target != ACCOUNT); // not-self (observable precondition)
        vm.assume(!hook.isAllowlisted(ACCOUNT, target)); // not-allowlisted (observable view)

        // Ghost pre-flight: same call shape as _isModule (:210). assume(!s) == precondition
        // _isModule(target)==false, stated observably rather than by pinning the address.
        (bool s,) = target.staticcall{gas: 30_000}(abi.encodeWithSelector(IS_MODULE_TYPE, uint256(0)));
        vm.assume(!s);

        value = svm.createUint256("value");
        vm.assume(value > 0);

        bytes memory msgData = _buildSingleMsgData(target, value);

        vm.prank(ACCOUNT);
        (ok, ret) = address(hook).call(msgData);
    }

    /// @notice OBSERVABLE (SG-P3-1 generalization of check_DenyETH): for a SINGLE call with
    ///         value>0 to a SYMBOLIC target that is not allowlisted, not the caller, and not a
    ///         module (isModuleType staticcall fails), preCheck reverts with exactly
    ///         ETHTransferNotAllowed(target, value). Source: DefaultSecurityHook.sol:199.
    ///         Asserts revert selector + args only — no branch-order reimplementation.
    function check_DenyETH_symbolicTarget() external {
        (address target, uint256 value, bool ok, bytes memory ret) = _denyETHSymbolicTarget();

        assert(!ok);
        assert(
            keccak256(ret)
                == keccak256(abi.encodeWithSelector(DefaultSecurityHook.ETHTransferNotAllowed.selector, target, value))
        );
    }

    /// @notice Reachability/vacuity witness for check_DenyETH_symbolicTarget: SAME precondition
    ///         set (including the ghost staticcall assume), guards on the exact
    ///         ETHTransferNotAllowed leaf and asserts false. Halmos MUST emit a counterexample;
    ///         none => the ghost-constrained space is empty (vacuous), do NOT report proven.
    function check_DenyETH_symbolicTarget_reachable() external {
        (address target, uint256 value, bool ok, bytes memory ret) = _denyETHSymbolicTarget();

        if (
            !ok
                && keccak256(ret)
                    == keccak256(
                        abi.encodeWithSelector(DefaultSecurityHook.ETHTransferNotAllowed.selector, target, value)
                    )
        ) {
            assert(false);
        }
    }

    /// @notice Guard-discrimination witness: the ETH gate is NOT trivially always-revert. With the
    ///         SAME target allowlisted for all selectors, preCheck does NOT revert even when value>0
    ///         (allowlist-first branch :188 returns before the ETH check). Asserts false on the
    ///         non-revert leaf so a counterexample witnesses that the gate discriminates on allowlist
    ///         state.
    function check_DenyETH_converseLive() external {
        _makeTargetNotModule();

        vm.prank(ACCOUNT);
        hook.onInstall("");
        // Allow-all selectors for TARGET => allSelectorsAllowed, so :188 returns.
        vm.prank(ACCOUNT);
        hook.setAllowlist(TARGET, new bytes4[](0));

        uint256 value = svm.createUint256("value");
        vm.assume(value > 0);

        bytes memory msgData = _buildSingleMsgData(TARGET, value);

        vm.prank(ACCOUNT);
        (bool ok,) = address(hook).call(msgData);

        // ok==true (no revert) => gate discriminates. Assert false on that leaf for a CEX witness.
        assert(!ok);
    }
}
