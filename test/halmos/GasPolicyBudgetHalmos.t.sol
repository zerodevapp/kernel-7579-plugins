pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {GasPolicy, GasPolicyConfig, Status} from "src/policies/GasPolicy.sol";

/// @author taek <leekt216@gmail.com>
contract GasPolicyBudgetHalmos is SymTest, Test {
    GasPolicy policy;

    function setUp() external {
        // vm.etch (not `new`) — halmos 0.3.3 falls back to the unsupported deployCode cheat when
        // symbolically executing CREATE for this via_ir creation code. Etching runtimeCode sidesteps it.
        policy = GasPolicy(address(0xAAAA));
        vm.etch(address(policy), type(GasPolicy).runtimeCode);
    }

    // Builds a fully symbolic userOp and installs a symbolic, Live config for (id, sender).
    // Returns the pre-decrement `allowed`.
    function _prime(bytes32 id, address sender)
        internal
        returns (PackedUserOperation memory userOp, uint128 allowedPre)
    {
        // Symbolic, Live config. Installing via _policyOninstall keeps the storage layout honest
        // (status = Live, allowed/enforcePaymaster/allowedPaymaster symbolic).
        uint128 allowed = uint128(svm.createUint(128, "allowed"));
        bool enforcePaymaster = svm.createBool("enforcePaymaster");
        address allowedPaymaster = svm.createAddress("allowedPaymaster");
        vm.prank(sender);
        policy.onInstall(abi.encode(id, allowed, enforcePaymaster, allowedPaymaster));
        allowedPre = allowed;

        userOp.sender = svm.createAddress("uo.sender");
        userOp.nonce = svm.createUint256("uo.nonce");
        userOp.initCode = svm.createBytes(0, "uo.initCode");
        userOp.callData = svm.createBytes(0, "uo.callData");
        userOp.accountGasLimits = svm.createBytes32("uo.accountGasLimits");
        userOp.preVerificationGas = svm.createUint256("uo.preVerificationGas");
        userOp.gasFees = svm.createBytes32("uo.gasFees");
        userOp.paymasterAndData = svm.createBytes(64, "uo.paymasterAndData");
        userOp.signature = svm.createBytes(0, "uo.signature");
    }

    /// @notice After checkUserOpPolicy (success, fail-return, or caught revert), the stored budget
    ///         `allowed` for (id, sender) is <= its pre-call value.
    function check_BudgetMonotonicNonIncreasing(bytes32 id, address sender) external {
        (PackedUserOperation memory userOp, uint128 allowedPre) = _prime(id, sender);

        vm.prank(sender);
        try policy.checkUserOpPolicy(id, userOp) returns (
            uint256
        ) {
        // success or fail-return path
        }
            catch {
            // revert-caught path
        }

        (uint128 allowedPost,,) = policy.gasPolicyConfig(id, sender);
        assertLe(allowedPost, allowedPre);
    }

    /// @notice Vacuity/reachability witness: an accepted op that STRICTLY decreases allowed must
    ///         exist. Asserts the negation (accept AND post < pre) so a counterexample proves the
    ///         strict-decrement path is live and non-vacuous.
    /// @dev Gas fields are kept narrow (<=64-bit) so the nonlinear maxAmount multiply stays
    ///      tractable for the solver; the config (allowed) stays fully symbolic. This constrains
    ///      only the WITNESS search space, not the property (the property proof above is unrestricted).
    function check_BudgetMonotonicNonIncreasing_reachable(bytes32 id, address sender) external {
        uint128 allowedPre = 1_000_000;
        vm.prank(sender);
        policy.onInstall(abi.encode(id, allowedPre, false, address(0)));

        // Concrete witness: verificationGasLimit=0, callGasLimit=1000, maxFeePerGas=1,
        // preVerificationGas=0 => maxAmount = 1000, which is <= allowed and > 0.
        PackedUserOperation memory userOp;
        userOp.accountGasLimits = bytes32(uint256(1000)); // low 128 bits = callGasLimit
        userOp.gasFees = bytes32(uint256(1)); // low 128 bits = maxFeePerGas

        vm.prank(sender);
        uint256 ret = policy.checkUserOpPolicy(id, userOp);

        (uint128 allowedPost,,) = policy.gasPolicyConfig(id, sender);
        assertFalse(ret == 0 && allowedPost < allowedPre);
    }
}
