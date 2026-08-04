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
/// @notice Halmos proof harness for DSH-BATCH-01 THROUGH the real calldata decoder
///         (closes the Certora TCB caveat: "a decoder bug would escape this property").
///         The batch enters via the REAL preCheck entry (DefaultSecurityHook.sol:136-141) so the
///         compiled solady LibERC7579.decodeBatch/getExecution calldata-pointer assembly is
///         exercised, not a Call[] struct model.
///
///         TAUTOLOGY GUARD (per dispatch): the executionData is HAND-ENCODED word-by-word from the
///         published ERC-7579 / ABI `Execution[]` layout via abi.encodePacked (see _encodeBatch2) —
///         it is NOT produced by LibERC7579's encode helpers, and not even by solc's abi.encode of a
///         matching struct — so the decoder is cross-checked against a genuinely independent encoder.
///
///         Property (iff, single biconditional): for a 2-element batch to non-allowlisted,
///         non-self, non-module targets, preCheck reverts iff ANY element violates a deny rule
///         (value_i > 0 or selector_i in the blocked set); otherwise it returns hex"".
contract DefaultSecurityHookBatchHalmos is SymTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    DefaultSecurityHook internal hook;

    // Distinct concrete addresses so target != msg.sender is structural (observable precondition
    // "both targets != account, non-allowlisted"). Both targets get REVERT stubs etched so their
    // isModuleType staticcall returns success==false => _isModule==false (non-module precondition).
    address internal constant ACCOUNT = address(uint160(uint256(keccak256("batch.account"))));
    address internal constant TARGET0 = address(uint160(uint256(keccak256("batch.target0"))));
    address internal constant TARGET1 = address(uint160(uint256(keccak256("batch.target1"))));

    function setUp() external {
        hook = DefaultSecurityHook(address(uint160(uint256(keccak256("DefaultSecurityHook")))));
        vm.etch(address(hook), type(DefaultSecurityHook).runtimeCode);
        // REVERT stubs (PUSH1 0 PUSH1 0 REVERT): staticcall fails => not a module.
        vm.etch(TARGET0, hex"60006000fd");
        vm.etch(TARGET1, hex"60006000fd");
    }

    /// @dev Independent SPEC restatement of the deny set (literal 4-byte constants, NOT read from
    ///      the impl's internal constants): ERC-20 transfer/approve/transferFrom/increaseAllowance/
    ///      decreaseAllowance, ERC-721 safeTransferFrom x2 + setApprovalForAll, ERC-1155
    ///      safeTransferFrom + safeBatchTransferFrom.
    function _specBlocked(bytes4 s) internal pure returns (bool) {
        return s == 0xa9059cbb || s == 0x095ea7b3 || s == 0x23b872dd || s == 0x39509351 || s == 0xa457c2d7
            || s == 0x42842e0e || s == 0xb88d4fde || s == 0xa22cb465 || s == 0xf242432a || s == 0x2eb2c2d6;
    }

    /// @dev HAND-ENCODED ERC-7579 batch executionData for exactly 2 executions, each with a 4-byte
    ///      calldata payload. Layout derived from the published ABI encoding of Execution[]
    ///      (Execution = (address target, uint256 value, bytes data)), word by word:
    ///        [0x000] 0x20   offset to the array
    ///        [0x020] 2      array length            (pointers.offset starts at 0x40)
    ///        [0x040] 0x40   elem0 offset, rel. to pointers.offset
    ///        [0x060] 0xe0   elem1 offset, rel. to pointers.offset (0x40 + elem0 size 0xa0)
    ///        elem_i (5 words = 0xa0): target | value | 0x60 (data offset rel. to elem start)
    ///                                 | 4 (data length) | selector right-padded to 32 bytes
    ///      Total 0x1c0 bytes. Deliberately NOT abi.encode of a struct array.
    function _encodeBatch2(uint256 v0, bytes4 s0, uint256 v1, bytes4 s1) internal pure returns (bytes memory) {
        return abi.encodePacked(
            abi.encodePacked(uint256(0x20), uint256(2), uint256(0x40), uint256(0xe0)),
            abi.encodePacked(uint256(uint160(TARGET0)), v0, uint256(0x60), uint256(4), bytes32(s0)),
            abi.encodePacked(uint256(uint160(TARGET1)), v1, uint256(0x60), uint256(4), bytes32(s1))
        );
    }

    /// @dev Full preCheck msgData: [0:4] dummy execute selector, then ABI-encoded
    ///      (bytes32 mode, bytes executionData) — the assembly at :126-131 dereferences the
    ///      executionData offset word at msgData[36:68], so the inner bytes must be ABI-framed.
    ///      mode high byte 0x01 = CALLTYPE_BATCH.
    function _buildBatchMsgData(uint256 v0, bytes4 s0, uint256 v1, bytes4 s1) internal view returns (bytes memory) {
        bytes32 mode = bytes32(uint256(0x01) << 248); // CALLTYPE_BATCH
        bytes memory param = abi.encodePacked(bytes4(0), abi.encode(mode, _encodeBatch2(v0, s0, v1, s1)));
        return abi.encodeWithSelector(hook.preCheck.selector, address(0), uint256(0), param);
    }

    /// @notice DSH-BATCH-01 through the REAL decoder (OBSERVABLE iff): with an initialized account
    ///         and a hand-encoded 2-element batch to non-allowlisted / non-self / non-module
    ///         targets, preCheck reverts iff ANY element has value>0 or a blocked selector
    ///         (spec-side deny set, independently restated); otherwise it returns hex"".
    ///         Both directions catch decoder bugs: a decoder that misreads value/selector flips the
    ///         revert side; a decoder that spuriously reverts (DecodingError) on well-formed input
    ///         flips the clean side.
    function check_BatchDenyThroughRealDecoder() external {
        vm.prank(ACCOUNT);
        hook.onInstall(""); // initialized, NO allowlist entries => allowlist branch never returns

        uint256 v0 = svm.createUint256("v0");
        uint256 v1 = svm.createUint256("v1");
        bytes4 s0 = svm.createBytes4("s0");
        bytes4 s1 = svm.createBytes4("s1");

        vm.prank(ACCOUNT);
        (bool ok, bytes memory ret) = address(hook).call(_buildBatchMsgData(v0, s0, v1, s1));

        bool bad = v0 > 0 || _specBlocked(s0) || v1 > 0 || _specBlocked(s1);
        if (bad) {
            assert(!ok); // any violating element => whole preCheck reverts
        } else {
            // clean batch => success AND return data is the ABI encoding of empty bytes
            assert(ok);
            assert(keccak256(ret) == keccak256(abi.encode(bytes(""))));
        }
    }

    /// @notice Reachability witness #1 (element-1-violates leg): v0==0, s0 pinned benign, v1>0
    ///         symbolic. Guards on the revert leaf then asserts false — Halmos MUST emit a
    ///         counterexample proving the second batch element is genuinely decoded and enforced
    ///         (the loop iterates past i=0). NO counterexample => leg dead => VACUOUS.
    function check_BatchDenyThroughRealDecoder_reachable_elem1Reverts() external {
        vm.prank(ACCOUNT);
        hook.onInstall("");

        uint256 v1 = svm.createUint256("v1");
        vm.assume(v1 > 0);

        vm.prank(ACCOUNT);
        (bool ok, bytes memory ret) =
            address(hook).call(_buildBatchMsgData(0, bytes4(0x11223344), v1, bytes4(0x55667788)));

        // Exact leaf: ETHTransferNotAllowed(TARGET1, v1) — element 1, real decoded args.
        if (
            !ok
                && keccak256(ret)
                    == keccak256(
                        abi.encodeWithSelector(DefaultSecurityHook.ETHTransferNotAllowed.selector, TARGET1, v1)
                    )
        ) {
            assert(false);
        }
    }

    /// @notice Reachability witness #2 (clean-batch success leg): both values 0, benign concrete
    ///         selectors. Guards on the success-with-empty-return leaf then asserts false — Halmos
    ///         MUST emit a counterexample proving a well-formed hand-encoded batch survives the
    ///         real decoder end-to-end. NO counterexample => success leg dead => VACUOUS.
    function check_BatchDenyThroughRealDecoder_reachable_clean() external {
        vm.prank(ACCOUNT);
        hook.onInstall("");

        vm.prank(ACCOUNT);
        (bool ok, bytes memory ret) =
            address(hook).call(_buildBatchMsgData(0, bytes4(0x11223344), 0, bytes4(0x55667788)));

        if (ok && keccak256(ret) == keccak256(abi.encode(bytes("")))) {
            assert(false);
        }
    }
}
