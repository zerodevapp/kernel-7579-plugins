// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {GasPolicy, GasPolicyConfig, Status} from "src/policies/GasPolicy.sol";
import {SIG_VALIDATION_SUCCESS_UINT, SIG_VALIDATION_FAILED_UINT} from "src/types/Constants.sol";

// Minimal cheatcode surface. Inheriting forge-std `Test` pulls in a base constructor that calls
// vm.deployCode(string) (StdConfig), which Halmos 0.3.3 does not support and fails setUp().
interface Vm {
    function assume(bool) external pure;
    function prank(address) external;
    function etch(address, bytes calldata) external;
}

/// @author taek <leekt216@gmail.com>
/// @notice Halmos proof harness for GasPolicy.checkUserOpPolicy budget accounting.
contract GasPolicyHalmos is SymTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    GasPolicy internal policy;

    // Fixed identifiers so storage reads/writes are concrete-keyed (Halmos-friendly).
    bytes32 internal constant ID = bytes32(uint256(0xABCD));
    address internal constant CALLER = address(0xCA11);

    function setUp() external {
        // Halmos 0.3.3 cannot execute GasPolicy's via_ir creation bytecode (routes to an
        // unsupported deployCode(string) cheat), so place the runtime code directly. GasPolicy has
        // no constructor logic (all state is set later via onInstall), so etch is state-equivalent.
        policy = GasPolicy(address(uint160(uint256(keccak256("GasPolicy")))));
        vm.etch(address(policy), type(GasPolicy).runtimeCode);
    }

    // Installs the policy for (ID, CALLER) with a symbolic budget and paymaster disabled,
    // so the paymaster branch cannot interfere with the pure budget-accounting property.
    function _install(uint128 allowed) internal {
        bytes memory data = abi.encodePacked(ID, abi.encode(allowed, false, address(0)));
        vm.prank(CALLER);
        policy.onInstall(data);
    }

    // Builds a PackedUserOperation whose gas-relevant fields carry the given symbolic values.
    // verificationGasLimit occupies the high 128 bits of accountGasLimits, callGasLimit the low 128.
    // maxFeePerGas occupies the low 128 bits of gasFees.
    function _userOp(
        uint256 preVerificationGas,
        uint128 verificationGasLimit,
        uint128 callGasLimit,
        uint128 maxFeePerGas
    ) internal pure returns (PackedUserOperation memory op) {
        op.accountGasLimits = bytes32((uint256(verificationGasLimit) << 128) | uint256(callGasLimit));
        op.preVerificationGas = preVerificationGas;
        op.gasFees = bytes32(uint256(maxFeePerGas)); // high 128 (priority fee) left zero, unused
    }

    /// @notice Budget decreases by exactly the TRUE uint256 cost, and no over-cap op passes.
    /// Combines success-exactness (a), over-cap rejection (b), and monotonicity (c) into the single
    /// invariant "post == pre - trueCost on success, never SUCCESS when trueCost > pre, post <= pre".
    function check_gasPolicy_noUnderCharge(
        uint128 allowed,
        uint256 preVerificationGas,
        uint128 verificationGasLimit,
        uint128 callGasLimit,
        uint128 maxFeePerGas
    ) external {
        // Bound operands so the TRUE product is representable in uint256 (dispatch: avoid ~2^320 wrap).
        // sum <= 2^128 and maxFeePerGas <= 2^128 => product <= 2^256, still >> 2^128 (over-cap region).
        uint256 sum = uint256(preVerificationGas) + uint256(verificationGasLimit) + uint256(callGasLimit);
        vm.assume(sum <= (uint256(1) << 128));
        // trueCost independently computed by the harness in full uint256 (NOT read from the contract).
        uint256 trueCost = sum * uint256(maxFeePerGas);

        _install(allowed);

        PackedUserOperation memory op = _userOp(preVerificationGas, verificationGasLimit, callGasLimit, maxFeePerGas);

        vm.prank(CALLER);
        (bool ok, bytes memory ret) = address(policy).call(abi.encodeCall(policy.checkUserOpPolicy, (ID, op)));

        (uint128 allowedPost,,) = policy.gasPolicyConfig(ID, CALLER);

        if (ok) {
            uint256 result = abi.decode(ret, (uint256));
            if (result == SIG_VALIDATION_SUCCESS_UINT) {
                // (a) success => true cost within budget and budget decremented by TRUE cost.
                assert(trueCost <= allowed);
                assert(uint256(allowedPost) == uint256(allowed) - trueCost);
            } else {
                // FAILED path leaves budget untouched.
                assert(uint256(allowedPost) == uint256(allowed));
            }
            // (b) an over-cap op must never reach SUCCESS.
            assert(!(trueCost > allowed && result == SIG_VALIDATION_SUCCESS_UINT));
        } else {
            // Revert (e.g. 0.8 overflow) leaves state unchanged.
            assert(uint256(allowedPost) == uint256(allowed));
        }
        // (c) monotone non-increasing budget.
        assert(uint256(allowedPost) <= uint256(allowed));
    }

    /// @notice Reachability witness: SUCCESS path is live. Asserts false on the SUCCESS leaf under the
    /// SAME precondition set; a counterexample proves the success path is satisfiable (non-vacuous).
    function check_gasPolicy_noUnderCharge_reachable(
        uint128 allowed,
        uint256 preVerificationGas,
        uint128 verificationGasLimit,
        uint128 callGasLimit,
        uint128 maxFeePerGas
    ) external {
        uint256 sum = uint256(preVerificationGas) + uint256(verificationGasLimit) + uint256(callGasLimit);
        vm.assume(sum <= (uint256(1) << 128));

        _install(allowed);
        PackedUserOperation memory op = _userOp(preVerificationGas, verificationGasLimit, callGasLimit, maxFeePerGas);

        vm.prank(CALLER);
        uint256 result = policy.checkUserOpPolicy(ID, op);

        // If SUCCESS is reachable, Halmos yields a counterexample here (proves path liveness).
        assert(result != SIG_VALIDATION_SUCCESS_UINT);
    }

    /// @notice Boundary reachability witness: the truncation boundary (trueCost == 2^128, low128 == 0)
    /// must be REJECTED. Asserts false on the SUCCESS leaf for that exact input; a counterexample would
    /// mean it was accepted (impl bug). NO counterexample => it is rejected as required.
    /// verificationGasLimit = 2^80, maxFeePerGas = 2^48 => product = 2^128 (low 128 bits all zero).
    function check_gasPolicy_truncationBoundary_rejected(uint128 allowed) external {
        _install(allowed);
        PackedUserOperation memory op = _userOp(0, uint128(uint256(1) << 80), 0, uint128(uint256(1) << 48));

        vm.prank(CALLER);
        (bool ok, bytes memory ret) = address(policy).call(abi.encodeCall(policy.checkUserOpPolicy, (ID, op)));

        // trueCost == 2^128 > allowed (allowed <= type(uint128).max < 2^128) => must NOT succeed.
        // If uint128 truncation were used instead, low128 == 0 would make maxAmount == 0 and this
        // would incorrectly SUCCEED.
        if (ok) {
            uint256 result = abi.decode(ret, (uint256));
            assert(result != SIG_VALIDATION_SUCCESS_UINT);
        }
    }

    // ---------------------------------------------------------------------------------------------
    // SUB-LEMMA: the uint128 truncation boundary is closed (family P = 2^128 + r * 2^48).
    // ---------------------------------------------------------------------------------------------

    /// @notice Sub-lemma: for the operand family whose TRUE uint256 product P >= 2^128, and any
    ///         uint128 budget (allowed < 2^128 < P), checkUserOpPolicy rejects AND leaves the budget
    ///         untouched. Base P = (2^80) * (2^48) = 2^128; symbolic remainder r in [0, 2^47) gives
    ///         P = (2^80 + r) * 2^48 = 2^128 + r*2^48 >= 2^128. Observable: not SUCCESS AND no decrement.
    function check_gasPolicy_truncationBoundaryFamily_rejectsNoDecrement(uint128 allowed, uint256 r) external {
        vm.assume(r < (uint256(1) << 47)); // keep preVerificationGas small: P just above 2^128, no wrap

        _install(allowed);
        (uint128 allowedPre,,) = policy.gasPolicyConfig(ID, CALLER);

        // verificationGasLimit = 2^80, maxFeePerGas = 2^48, preVerificationGas = r, callGasLimit = 0.
        PackedUserOperation memory op = _userOp(r, uint128(uint256(1) << 80), 0, uint128(uint256(1) << 48));

        vm.prank(CALLER);
        uint256 result = policy.checkUserOpPolicy(ID, op);

        (uint128 allowedPost,,) = policy.gasPolicyConfig(ID, CALLER);

        // Fixed reject outcome at/above the numeric boundary; budget must not be decremented.
        assert(result != SIG_VALIDATION_SUCCESS_UINT && allowedPost == allowedPre);
    }

    /// @notice Reachability witness for the sub-lemma: a NON-boundary op (small product P <= allowed)
    ///         DOES return SUCCESS, proving the reject branch is discriminating (not a universal
    ///         revert/reject). Asserts false on the SUCCESS leaf; a counterexample => path is live.
    function check_gasPolicy_truncationBoundaryFamily_rejectsNoDecrement_reachable(uint128 allowed) external {
        vm.assume(allowed >= 1000); // budget large enough to admit a tiny op

        _install(allowed);

        PackedUserOperation memory op; // all-zero gas fields => P = 0 <= allowed => SUCCESS branch
        vm.prank(CALLER);
        uint256 result = policy.checkUserOpPolicy(ID, op);

        assert(result != SIG_VALIDATION_SUCCESS_UINT);
    }
}
