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
/// @notice Halmos proof harness for the DefaultSecurityHook blocked-selector gate (spec
///         §4.5-4.8, §5.1; DSH-ALLOW-01). Own file per property cluster (same convention as
///         DefaultSecurityHookDenyETHHalmos). Etch-deploy is state-equivalent: the hook has no
///         constructor logic (all state via onInstall).
///
///         Property: for an initialized account and a SINGLE call with target NOT allowlisted,
///         target != account, _isModule(target)==false, value==0 and data.length>=4, preCheck
///         reverts TokenTransferNotAllowed(target, selector) IFF the 4-byte selector is one of
///         the 10 spec-§4.8 blocked selectors; otherwise it succeeds. CONVERSE: a target
///         allowlisted with EMPTY selectors (allSelectorsAllowed) never reverts, for any
///         selector and any value.
contract DefaultSecurityHookBlockedSelectorHalmos is SymTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    DefaultSecurityHook internal hook;

    // Distinct concrete addresses so target != msg.sender is structurally guaranteed. TARGET gets
    // a REVERT stub etched so its isModuleType staticcall returns success==false =>
    // _isModule(TARGET)==false, pinning the not-a-module precondition while the selector stays
    // fully symbolic.
    address internal constant ACCOUNT = address(uint160(uint256(keccak256("blocked.account"))));
    address internal constant TARGET = address(uint160(uint256(keccak256("blocked.target"))));

    function setUp() external {
        hook = DefaultSecurityHook(address(uint160(uint256(keccak256("DefaultSecurityHook")))));
        vm.etch(address(hook), type(DefaultSecurityHook).runtimeCode);
    }

    /// @dev Etch a REVERT stub (PUSH1 0 PUSH1 0 REVERT) at TARGET so
    ///      target.staticcall(isModuleType,...) returns success==false => _isModule(TARGET)==false.
    function _makeTargetNotModule() internal {
        vm.etch(TARGET, hex"60006000fd");
    }

    /// @dev SPEC ORACLE (§4.8): the 10 blocked selectors as LITERAL constants transcribed from the
    ///      spec, deliberately NOT derived from IERC20/IERC721/IERC1155 `.selector` and NOT calling
    ///      the implementation's _isBlockedSelector — an independent enumeration so the check is
    ///      not tautological against the implementation's own constant folding.
    function _specBlocked(bytes4 selector) internal pure returns (bool) {
        return selector == bytes4(0xa9059cbb) // transfer(address,uint256)
            || selector == bytes4(0x095ea7b3) // approve(address,uint256)
            || selector == bytes4(0x23b872dd) // transferFrom(address,address,uint256)
            || selector == bytes4(0x39509351) // increaseAllowance(address,uint256)
            || selector == bytes4(0xa457c2d7) // decreaseAllowance(address,uint256)
            || selector == bytes4(0x42842e0e) // safeTransferFrom(address,address,uint256)
            || selector == bytes4(0xb88d4fde) // safeTransferFrom(address,address,uint256,bytes)
            || selector == bytes4(0xa22cb465) // setApprovalForAll(address,bool)
            || selector == bytes4(0xf242432a) // 1155 safeTransferFrom(addr,addr,uint256,uint256,bytes)
            || selector == bytes4(0x2eb2c2d6); // 1155 safeBatchTransferFrom(addr,addr,uint[],uint[],bytes)
    }

    /// @dev Build preCheck msgData for a CALLTYPE_SINGLE call (mode word all-zero => callType 0x00),
    ///      packed executionData = target(20) || value(32) || selector(4) = 0x38 bytes > 0x33, so
    ///      LibERC7579.decodeSingle succeeds. preCheck reads the inner `msgData` param as: [0:4]
    ///      dummy selector, [4:36] mode, [36:68] ABI offset for the executionData bytes, then
    ///      length + data — hence dummy-selector || abi.encode(mode, executionData).
    function _buildSingleMsgData(address target, uint256 value, bytes4 selector)
        internal
        view
        returns (bytes memory msgData)
    {
        bytes32 mode = bytes32(0); // high byte == 0x00 => CALLTYPE_SINGLE
        bytes memory executionData = abi.encodePacked(target, value, selector);
        bytes memory param = abi.encodePacked(bytes4(0), abi.encode(mode, executionData));
        msgData = abi.encodeWithSelector(hook.preCheck.selector, address(0), uint256(0), param);
    }

    /// @notice OBSERVABLE, EXACT (iff): with ACCOUNT initialized (real onInstall), TARGET not
    ///         allowlisted (entry.allowed==false), TARGET != ACCOUNT, _isModule(TARGET)==false and
    ///         value==0, a SINGLE call with a fully symbolic 4-byte selector makes preCheck revert
    ///         with exactly TokenTransferNotAllowed(TARGET, selector) IF the selector is in the
    ///         spec-§4.8 10-selector set, and SUCCEED (no revert of any kind) otherwise.
    ///         Source: DefaultSecurityHook.sol:202-205 (_checkCall blocked-selector leg),
    ///         :214-219 (_isBlockedSelector), :112-147 (preCheck). The success side of the iff
    ///         rules out both false denies and shadowing by a different revert.
    function check_BlockedSelectorDenyExact() external {
        _makeTargetNotModule();

        // Initialized via REAL onInstall; NO setAllowlist for TARGET => entry.allowed==false, so
        // the allowlist-first branch (:187-190) cannot return and control reaches the gates.
        vm.prank(ACCOUNT);
        hook.onInstall("");

        bytes4 selector = svm.createBytes4("selector"); // fully symbolic: covers all 2^32 selectors

        bytes memory msgData = _buildSingleMsgData(TARGET, 0, selector);

        vm.prank(ACCOUNT);
        (bool ok, bytes memory ret) = address(hook).call(msgData);

        if (_specBlocked(selector)) {
            // Deny side: exact revert, selector AND abi-encoded (target, selector) args.
            assert(!ok);
            assert(
                keccak256(ret)
                    == keccak256(
                        abi.encodeWithSelector(DefaultSecurityHook.TokenTransferNotAllowed.selector, TARGET, selector)
                    )
            );
        } else {
            // Exactness converse within the deny region: any NON-blocked selector sails through
            // (no TokenTransferNotAllowed, no other revert).
            assert(ok);
        }
    }

    /// @notice Reachability/vacuity witness for check_BlockedSelectorDenyExact: guards on the
    ///         exact TokenTransferNotAllowed revert leaf under the SAME preconditions, then asserts
    ///         false so Halmos MUST emit a counterexample (a concrete blocked selector reaching the
    ///         :204 revert — also witnessing that the module check CAN return false, i.e. the leaf
    ///         is not shadowed by ModuleCallNotAllowed). NO counterexample => leaf dead /
    ///         preconditions unsatisfiable (VACUOUS — report as such, not proven).
    function check_BlockedSelectorDenyExact_reachable() external {
        _makeTargetNotModule();

        vm.prank(ACCOUNT);
        hook.onInstall("");

        bytes4 selector = svm.createBytes4("selector");

        bytes memory msgData = _buildSingleMsgData(TARGET, 0, selector);

        vm.prank(ACCOUNT);
        (bool ok, bytes memory ret) = address(hook).call(msgData);

        if (
            !ok
                && keccak256(ret)
                    == keccak256(
                        abi.encodeWithSelector(DefaultSecurityHook.TokenTransferNotAllowed.selector, TARGET, selector)
                    )
        ) {
            assert(false);
        }
    }

    /// @notice CONVERSE rule (spec §5.1, certora :93 counterpart): once TARGET is allowlisted with
    ///         EMPTY selectors (allSelectorsAllowed==true), preCheck NEVER reverts — for ANY
    ///         symbolic 4-byte selector (including the 10 blocked ones) and ANY symbolic value
    ///         (including value>0). Source: _checkCall :187-188 returns before every gate.
    ///         OBSERVABLE: asserts non-revert of the external call, not a re-read of allowlist
    ///         storage (non-tautological).
    function check_BlockedSelectorAllowlistedNeverReverts() external {
        _makeTargetNotModule();

        vm.prank(ACCOUNT);
        hook.onInstall("");
        // Blanket allowlist: empty selector array => allSelectorsAllowed==true.
        vm.prank(ACCOUNT);
        hook.setAllowlist(TARGET, new bytes4[](0));

        bytes4 selector = svm.createBytes4("selector"); // symbolic: includes all blocked selectors
        uint256 value = svm.createUint256("value"); // symbolic: includes value>0

        bytes memory msgData = _buildSingleMsgData(TARGET, value, selector);

        vm.prank(ACCOUNT);
        (bool ok,) = address(hook).call(msgData);

        assert(ok);
    }

    /// @notice Pass-witness / reachability companion for the converse rule: guards on the
    ///         allowlisted-success branch (ok==true) under the SAME preconditions, then asserts
    ///         false so Halmos MUST emit a counterexample proving the success path is live (the
    ///         blanket-allowlist return at :188 is actually reached, the assert(ok) above is not
    ///         vacuously ranging over an empty path set). NO counterexample => VACUOUS.
    function check_BlockedSelectorAllowlistedNeverReverts_reachable() external {
        _makeTargetNotModule();

        vm.prank(ACCOUNT);
        hook.onInstall("");
        vm.prank(ACCOUNT);
        hook.setAllowlist(TARGET, new bytes4[](0));

        bytes4 selector = svm.createBytes4("selector");
        uint256 value = svm.createUint256("value");

        bytes memory msgData = _buildSingleMsgData(TARGET, value, selector);

        vm.prank(ACCOUNT);
        (bool ok,) = address(hook).call(msgData);

        if (ok) {
            assert(false);
        }
    }
}
