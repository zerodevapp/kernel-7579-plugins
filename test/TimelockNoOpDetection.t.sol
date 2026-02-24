// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {IAccountExecute} from "account-abstraction/interfaces/IAccountExecute.sol";
import {IERC7579Execution} from "openzeppelin-contracts/contracts/interfaces/draft-IERC7579.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";
import {TimelockPolicy} from "src/policies/TimelockPolicy.sol";

/// @title TimelockPolicyHarness
/// @notice Exposes internal no-op detection functions for unit testing
contract TimelockPolicyHarness is TimelockPolicy {
    function exposed_isNoOpCalldata(bytes calldata callData) external pure returns (bool) {
        return _isNoOpCalldata(callData);
    }

    function exposed_isNoOpERC7579Execute(bytes calldata callData) external pure returns (bool) {
        return _isNoOpERC7579Execute(callData);
    }
}

/// @title TimelockNoOpDetectionTest
/// @notice Tests for the no-op calldata detection logic in TimelockPolicy.
///         Uses LibERC7579 to construct modes and execution data, confirming compatibility
///         with Solady's decodeSingle() which requires executionCalldata.length >= 52.
contract TimelockNoOpDetectionTest is Test {
    TimelockPolicyHarness harness;

    function setUp() public {
        harness = new TimelockPolicyHarness();
    }

    // ─── Helpers ────────────────────────────────────────────────────────

    /// @dev Encode a single-call mode via LibERC7579
    function _singleMode() internal pure returns (bytes32) {
        return LibERC7579.encodeMode(LibERC7579.CALLTYPE_SINGLE, LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes22(0));
    }

    /// @dev Build a single-call no-op: execute(singleMode, abi.encodePacked(address(0), uint256(0)))
    function _erc7579NoOp() internal pure returns (bytes memory) {
        return abi.encodeWithSelector(
            IERC7579Execution.execute.selector, _singleMode(), abi.encodePacked(address(0), uint256(0))
        );
    }

    /// @dev Build the old (broken) no-op: execute(singleMode, "") — 100 bytes, decodeSingle would revert
    function _erc7579NoOpOldFormat() internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IERC7579Execution.execute.selector, _singleMode(), "");
    }

    /// @dev Build an execute call with a specific mode and execution data
    function _erc7579Execute(bytes32 mode, bytes memory executionCalldata) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IERC7579Execution.execute.selector, mode, executionCalldata);
    }

    // ─── Case 1: Empty calldata ─────────────────────────────────────────

    function test_NoOp_EmptyCalldata() public view {
        assertTrue(harness.exposed_isNoOpCalldata(""));
    }

    // ─── Case 2: ERC-7579 execute with minimal execution data ───────────

    function test_NoOp_ERC7579Execute_ZeroTarget() public view {
        bytes memory callData = _erc7579NoOp();
        assertTrue(harness.exposed_isNoOpCalldata(callData));
        assertTrue(harness.exposed_isNoOpERC7579Execute(callData));
    }

    /// @notice Verify the calldata length is 164 (standard ABI padded encoding)
    function test_NoOp_ERC7579Execute_CorrectLength() public pure {
        bytes memory callData = _erc7579NoOp();
        // selector(4) + mode(32) + offset(32) + length(32) + data(52 padded to 64) = 164
        assertEq(callData.length, 164);
    }

    // ─── Case 2 rejections ──────────────────────────────────────────────

    /// @notice Non-zero target could trigger receive()/fallback() — not a no-op
    function test_Reject_ERC7579Execute_NonZeroTarget() public view {
        bytes memory callData = _erc7579Execute(_singleMode(), abi.encodePacked(address(0xdead), uint256(0)));
        assertFalse(harness.exposed_isNoOpCalldata(callData));
        assertFalse(harness.exposed_isNoOpERC7579Execute(callData));
    }

    function testFuzz_Reject_ERC7579Execute_NonZeroTarget(address target) public view {
        vm.assume(target != address(0));
        bytes memory callData = _erc7579Execute(_singleMode(), abi.encodePacked(target, uint256(0)));
        assertFalse(harness.exposed_isNoOpCalldata(callData));
    }

    /// @notice Old 100-byte format (empty executionCalldata) must be rejected.
    ///         decodeSingle("") would revert, so this can never be a valid no-op.
    function test_Reject_ERC7579Execute_OldEmptyFormat() public view {
        bytes memory callData = _erc7579NoOpOldFormat();
        assertEq(callData.length, 100);
        assertFalse(harness.exposed_isNoOpCalldata(callData));
        assertFalse(harness.exposed_isNoOpERC7579Execute(callData));
    }

    /// @notice Non-zero value means ETH transfer — not a no-op
    function test_Reject_ERC7579Execute_NonZeroValue() public view {
        bytes memory callData = _erc7579Execute(_singleMode(), abi.encodePacked(address(0), uint256(1 ether)));
        assertFalse(harness.exposed_isNoOpCalldata(callData));
    }

    function testFuzz_Reject_ERC7579Execute_NonZeroValue(uint256 value) public view {
        vm.assume(value > 0);
        bytes memory callData = _erc7579Execute(_singleMode(), abi.encodePacked(address(0), value));
        assertFalse(harness.exposed_isNoOpCalldata(callData));
    }

    /// @notice CALLTYPE_BATCH should be rejected
    function test_Reject_ERC7579Execute_BatchMode() public view {
        bytes32 mode =
            LibERC7579.encodeMode(LibERC7579.CALLTYPE_BATCH, LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes22(0));
        bytes memory callData = _erc7579Execute(mode, abi.encodePacked(address(0), uint256(0)));
        assertFalse(harness.exposed_isNoOpCalldata(callData));
    }

    /// @notice CALLTYPE_DELEGATECALL should be rejected
    function test_Reject_ERC7579Execute_DelegatecallMode() public view {
        bytes32 mode =
            LibERC7579.encodeMode(LibERC7579.CALLTYPE_DELEGATECALL, LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes22(0));
        bytes memory callData = _erc7579Execute(mode, abi.encodePacked(address(0), uint256(0)));
        assertFalse(harness.exposed_isNoOpCalldata(callData));
    }

    /// @notice CALLTYPE_STATICCALL should be rejected
    function test_Reject_ERC7579Execute_StaticcallMode() public view {
        bytes32 mode =
            LibERC7579.encodeMode(LibERC7579.CALLTYPE_STATICCALL, LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes22(0));
        bytes memory callData = _erc7579Execute(mode, abi.encodePacked(address(0), uint256(0)));
        assertFalse(harness.exposed_isNoOpCalldata(callData));
    }

    /// @notice executionCalldata with inner calldata (length > 52) should be rejected
    function test_Reject_ERC7579Execute_HasInnerCalldata() public view {
        bytes memory callData = _erc7579Execute(_singleMode(), abi.encodePacked(address(0), uint256(0), hex"deadbeef"));
        assertFalse(harness.exposed_isNoOpCalldata(callData));
    }

    /// @notice Wrong selector should be rejected
    function test_Reject_ERC7579Execute_WrongSelector() public view {
        bytes memory callData =
            abi.encodeWithSelector(bytes4(0xdeadbeef), _singleMode(), abi.encodePacked(address(0), uint256(0)));
        assertFalse(harness.exposed_isNoOpERC7579Execute(callData));
    }

    /// @notice Calldata too short to contain valid execution data
    function test_Reject_ERC7579Execute_TooShort() public view {
        // Only 20 bytes of exec data — decodeSingle needs > 0x33
        bytes memory callData = abi.encodeWithSelector(IERC7579Execution.execute.selector, _singleMode(), bytes20(0));
        assertFalse(harness.exposed_isNoOpERC7579Execute(callData));
    }

    // ─── Case 3: executeUserOp + empty ──────────────────────────────────

    function test_NoOp_ExecuteUserOpSelectorOnly() public view {
        bytes memory callData = abi.encodePacked(IAccountExecute.executeUserOp.selector);
        assertEq(callData.length, 4);
        assertTrue(harness.exposed_isNoOpCalldata(callData));
    }

    // ─── Case 4: executeUserOp + ERC-7579 no-op ────────────────────────

    function test_NoOp_ExecuteUserOpWrappedERC7579() public view {
        bytes memory callData = abi.encodePacked(IAccountExecute.executeUserOp.selector, _erc7579NoOp());
        assertTrue(harness.exposed_isNoOpCalldata(callData));
    }

    /// @notice Wrapped old format should also be rejected
    function test_Reject_ExecuteUserOpWrappedOldFormat() public view {
        bytes memory callData = abi.encodePacked(IAccountExecute.executeUserOp.selector, _erc7579NoOpOldFormat());
        assertFalse(harness.exposed_isNoOpCalldata(callData));
    }

    /// @notice Wrapped ERC-7579 with non-zero target should be rejected
    function test_Reject_ExecuteUserOpWrappedNonZeroTarget() public view {
        bytes memory callData = abi.encodePacked(
            IAccountExecute.executeUserOp.selector,
            _erc7579Execute(_singleMode(), abi.encodePacked(address(0xdead), uint256(0)))
        );
        assertFalse(harness.exposed_isNoOpCalldata(callData));
    }

    /// @notice Wrapped ERC-7579 with non-zero value should be rejected
    function test_Reject_ExecuteUserOpWrappedNonZeroValue() public view {
        bytes memory callData = abi.encodePacked(
            IAccountExecute.executeUserOp.selector,
            _erc7579Execute(_singleMode(), abi.encodePacked(address(0), uint256(1)))
        );
        assertFalse(harness.exposed_isNoOpCalldata(callData));
    }

    /// @notice Wrapped ERC-7579 with batch mode should be rejected
    function test_Reject_ExecuteUserOpWrappedBatchMode() public view {
        bytes32 mode =
            LibERC7579.encodeMode(LibERC7579.CALLTYPE_BATCH, LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes22(0));
        bytes memory callData = abi.encodePacked(
            IAccountExecute.executeUserOp.selector, _erc7579Execute(mode, abi.encodePacked(address(0), uint256(0)))
        );
        assertFalse(harness.exposed_isNoOpCalldata(callData));
    }

    // ─── Non-no-op patterns ─────────────────────────────────────────────

    function test_Reject_RandomCalldata() public view {
        assertFalse(harness.exposed_isNoOpCalldata(hex"deadbeef"));
    }

    function test_Reject_ExecuteUserOpWithNonERC7579Data() public view {
        bytes memory callData = abi.encodePacked(
            IAccountExecute.executeUserOp.selector, hex"cafebabe0000000000000000000000000000000000000000"
        );
        assertFalse(harness.exposed_isNoOpCalldata(callData));
    }

    /// @notice Real ERC-7579 execute with actual inner calldata (not a no-op)
    function test_Reject_ERC7579Execute_RealExecution() public view {
        bytes memory callData = _erc7579Execute(
            _singleMode(),
            abi.encodePacked(
                address(0xdead), uint256(0), abi.encodeWithSignature("transfer(address,uint256)", address(1), 100)
            )
        );
        assertFalse(harness.exposed_isNoOpCalldata(callData));
    }
}
