// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import {GasPolicy} from "src/policies/GasPolicy.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_FAILED_UINT} from "src/types/Constants.sol";

/// @notice Regression test for GasPolicy: the gas-cost `maxAmount` must not be computed/compared
/// with an implicit uint128 downcast, since an op whose TRUE uint256 cost is a multiple of 2^128
/// (residue 0 in the low 128 bits) would truncate to 0 and sail under any nonzero budget while the
/// full multi-billion-gas cost is silently never charged. Comparing the full uint256
/// product against `allowed` blocks this: the over-cap op is
/// rejected and the budget is left untouched.
contract OverflowVerifyTest is Test {
    address constant WALLET = address(0xA11CE);

    GasPolicy policy;

    function setUp() public {
        policy = new GasPolicy();
    }

    function test_TF01_OverflowTruncationExploit_IsBlocked() public {
        bytes32 id = keccak256("POLICY_ID_1");
        uint128 allowed = 1e18;

        vm.prank(WALLET);
        policy.onInstall(abi.encodePacked(id, abi.encode(allowed, false, address(0))));

        // verificationGasLimit = 2^80, callGasLimit = 0, preVerificationGas = 0, maxFeePerGas = 2^48.
        // True cost = 2^80 * 2^48 = 2^128, whose low 128 bits truncate to exactly 0 -- the classic
        // uint128-downcast edge case: comparing 0 < allowed would incorrectly pass for free.
        uint128 verificationGasLimit = uint128(2 ** 80);
        uint128 callGasLimit = 0;
        uint128 maxFeePerGas = uint128(2 ** 48);

        uint256 trueCost = (uint256(0) + verificationGasLimit + callGasLimit) * maxFeePerGas;
        assertEq(trueCost, 2 ** 128, "true cost should be exactly 2^128");
        assertEq(uint128(trueCost), 0, "low-128 truncated residue is 0 -- the edge case precondition");
        assertGt(trueCost, allowed, "true cost must exceed the installed budget");

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: WALLET,
            nonce: 0,
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(abi.encodePacked(verificationGasLimit, callGasLimit)),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(maxFeePerGas, maxFeePerGas)),
            paymasterAndData: "",
            signature: ""
        });

        vm.prank(WALLET);
        uint256 result = policy.checkUserOpPolicy(id, userOp);

        assertEq(result, SIG_VALIDATION_FAILED_UINT, "over-cap op must be rejected despite zero low-128 residue");

        (uint128 remaining,,) = policy.gasPolicyConfig(id, WALLET);
        assertEq(remaining, allowed, "budget must be untouched -- the exploit must not drain it for free");
    }
}
