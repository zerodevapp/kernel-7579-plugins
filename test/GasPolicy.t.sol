// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {PolicyTestBase} from "./base/PolicyTestBase.sol";
import {GasPolicy, Status} from "src/policies/GasPolicy.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IModule} from "src/interfaces/IERC7579Modules.sol";
import {SIG_VALIDATION_FAILED_UINT, SIG_VALIDATION_SUCCESS_UINT} from "src/types/Constants.sol";

contract GasPolicyTest is PolicyTestBase {
    uint128 constant ALLOWED = 1_000_000;
    // valid op: (preVerificationGas 0 + verificationGasLimit 100 + callGasLimit 100) * maxFeePerGas 1 = 200
    uint128 constant VALID_GAS_LIMIT = 100;
    uint128 constant VALID_FEE = 1;
    // invalid op: (0 + 1_000_000 + 1_000_000) * 1 = 2_000_000 > ALLOWED
    uint128 constant INVALID_GAS_LIMIT = 1_000_000;

    address paymaster = address(0xBEEF);
    address otherPaymaster = address(0xCAFE);

    function deployModule() internal override returns (IModule) {
        return new GasPolicy();
    }

    function _initializeTest() internal override {}

    function installData() internal pure override returns (bytes memory) {
        return abi.encode(ALLOWED, false, address(0));
    }

    function _installDataWithPaymaster(uint128 allowed, bool enforcePaymaster, address allowedPaymaster)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(allowed, enforcePaymaster, allowedPaymaster);
    }

    function _userOp(uint128 gasLimit, uint128 fee, bytes memory paymasterAndData)
        internal
        pure
        returns (PackedUserOperation memory)
    {
        return PackedUserOperation({
            sender: WALLET,
            nonce: 0,
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(abi.encodePacked(gasLimit, gasLimit)),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(fee, fee)),
            paymasterAndData: paymasterAndData,
            signature: ""
        });
    }

    function _userOpRaw(
        uint128 verificationGasLimit,
        uint128 callGasLimit,
        uint256 preVerificationGas,
        uint128 maxFeePerGas,
        bytes memory paymasterAndData
    ) internal pure returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: WALLET,
            nonce: 0,
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(abi.encodePacked(verificationGasLimit, callGasLimit)),
            preVerificationGas: preVerificationGas,
            gasFees: bytes32(abi.encodePacked(maxFeePerGas, maxFeePerGas)),
            paymasterAndData: paymasterAndData,
            signature: ""
        });
    }

    function validUserOp() internal pure override returns (PackedUserOperation memory) {
        return _userOp(VALID_GAS_LIMIT, VALID_FEE, "");
    }

    function invalidUserOp() internal pure override returns (PackedUserOperation memory) {
        return _userOp(INVALID_GAS_LIMIT, VALID_FEE, "");
    }

    function validSignatureData(bytes32) internal pure override returns (address sender, bytes memory signature) {
        return (WALLET, "");
    }

    function invalidSignatureData(bytes32) internal pure override returns (address sender, bytes memory signature) {
        return (WALLET, "");
    }

    // GasPolicy's checkSignaturePolicy ignores sender/hash/sig entirely -- it only gates on
    // policy status. The generic base "fail" test assumes sig data content can flip the result,
    // which is impossible here, so we cover the real failure mode (not-Live) directly instead.
    function testPolicyCheckSignaturePolicyFail() public payable override {
        GasPolicy policy = GasPolicy(address(module));
        // never installed -> status is NA, not Live
        vm.prank(WALLET);
        vm.expectRevert();
        policy.checkSignaturePolicy(policyId(), WALLET, keccak256("hash"), "");
    }

    function _afterInstallCheck(bytes32 id) internal view override {
        (Status s) = GasPolicy(address(module)).status(id, WALLET);
        assertTrue(s == Status.Live, "status should be Live after install");
    }

    function _afterUninstallCheck(bytes32 id) internal view override {
        (Status s) = GasPolicy(address(module)).status(id, WALLET);
        assertTrue(s == Status.Deprecated, "status should be Deprecated after uninstall");
    }

    // ---------------------------------------------------------------------
    // install / uninstall state machine (beyond PolicyTestBase generic ones)
    // ---------------------------------------------------------------------

    function test_install_StoresConfig() public {
        GasPolicy policy = GasPolicy(address(module));
        vm.prank(WALLET);
        policy.onInstall(abi.encodePacked(policyId(), installData()));

        (uint128 allowed, bool enforcePaymaster, address allowedPaymaster) = policy.gasPolicyConfig(policyId(), WALLET);
        assertEq(allowed, ALLOWED, "allowed should match installData");
        assertFalse(enforcePaymaster, "enforcePaymaster should be false");
        assertEq(allowedPaymaster, address(0), "allowedPaymaster should be zero");
    }

    function test_uninstall_WhenNotLive_ShouldRevert() public {
        GasPolicy policy = GasPolicy(address(module));
        // never installed -> status is NA
        vm.prank(WALLET);
        vm.expectRevert();
        policy.onUninstall(abi.encodePacked(policyId(), installData()));
    }

    function test_uninstall_WhenAlreadyDeprecated_ShouldRevert() public {
        GasPolicy policy = GasPolicy(address(module));
        vm.startPrank(WALLET);
        policy.onInstall(abi.encodePacked(policyId(), installData()));
        policy.onUninstall(abi.encodePacked(policyId(), installData()));

        vm.expectRevert();
        policy.onUninstall(abi.encodePacked(policyId(), installData()));
        vm.stopPrank();
    }

    function test_reinstall_AfterUninstall_ShouldRevert() public {
        // status is Deprecated, not NA, so re-install must revert too
        GasPolicy policy = GasPolicy(address(module));
        vm.startPrank(WALLET);
        policy.onInstall(abi.encodePacked(policyId(), installData()));
        policy.onUninstall(abi.encodePacked(policyId(), installData()));

        vm.expectRevert();
        policy.onInstall(abi.encodePacked(policyId(), installData()));
        vm.stopPrank();
    }

    // ---------------------------------------------------------------------
    // checkUserOpPolicy - not Live
    // ---------------------------------------------------------------------

    function test_checkUserOpPolicy_WhenNotLive_ShouldRevert() public {
        GasPolicy policy = GasPolicy(address(module));
        PackedUserOperation memory userOp = validUserOp();

        vm.prank(WALLET);
        vm.expectRevert();
        policy.checkUserOpPolicy(policyId(), userOp);
    }

    // ---------------------------------------------------------------------
    // checkUserOpPolicy - budget accounting
    // ---------------------------------------------------------------------

    function test_checkUserOpPolicy_WhenWithinBudget_ShouldPassAndDecrement() public {
        GasPolicy policy = GasPolicy(address(module));
        vm.prank(WALLET);
        policy.onInstall(abi.encodePacked(policyId(), installData()));

        uint256 expectedCost = uint256(VALID_GAS_LIMIT) * 2 * VALID_FEE; // 200

        vm.prank(WALLET);
        uint256 result = policy.checkUserOpPolicy(policyId(), validUserOp());

        assertEq(result, SIG_VALIDATION_SUCCESS_UINT, "should succeed within budget");

        (uint128 remaining,,) = policy.gasPolicyConfig(policyId(), WALLET);
        assertEq(remaining, ALLOWED - expectedCost, "allowed should be decremented by cost");
    }

    function test_checkUserOpPolicy_WhenOverBudget_ShouldFailWithoutDecrement() public {
        GasPolicy policy = GasPolicy(address(module));
        vm.prank(WALLET);
        policy.onInstall(abi.encodePacked(policyId(), installData()));

        vm.prank(WALLET);
        uint256 result = policy.checkUserOpPolicy(policyId(), invalidUserOp());

        assertEq(result, SIG_VALIDATION_FAILED_UINT, "should fail when over budget");

        (uint128 remaining,,) = policy.gasPolicyConfig(policyId(), WALLET);
        assertEq(remaining, ALLOWED, "allowed should NOT be decremented on failure");
    }

    function test_checkUserOpPolicy_WhenExactlyAtBudget_ShouldPass() public {
        // boundary: maxAmount == allowed exactly -> passes (only strictly-greater fails)
        GasPolicy policy = GasPolicy(address(module));
        uint128 small = 200; // matches validUserOp cost exactly
        vm.prank(WALLET);
        policy.onInstall(abi.encodePacked(policyId(), _installDataWithPaymaster(small, false, address(0))));

        vm.prank(WALLET);
        uint256 result = policy.checkUserOpPolicy(policyId(), validUserOp());

        assertEq(result, SIG_VALIDATION_SUCCESS_UINT, "maxAmount == allowed should pass");

        (uint128 remaining,,) = policy.gasPolicyConfig(policyId(), WALLET);
        assertEq(remaining, 0, "budget should be fully consumed");
    }

    function test_checkUserOpPolicy_WhenOneWeiOverBudget_ShouldFail() public {
        GasPolicy policy = GasPolicy(address(module));
        uint128 small = 199; // one less than validUserOp cost of 200
        vm.prank(WALLET);
        policy.onInstall(abi.encodePacked(policyId(), _installDataWithPaymaster(small, false, address(0))));

        vm.prank(WALLET);
        uint256 result = policy.checkUserOpPolicy(policyId(), validUserOp());

        assertEq(result, SIG_VALIDATION_FAILED_UINT, "maxAmount == allowed + 1 should fail");
    }

    function test_checkUserOpPolicy_MultipleOps_ShouldDecrementCumulatively() public {
        GasPolicy policy = GasPolicy(address(module));
        vm.prank(WALLET);
        policy.onInstall(abi.encodePacked(policyId(), installData()));

        uint256 costPerOp = uint256(VALID_GAS_LIMIT) * 2 * VALID_FEE; // 200

        vm.startPrank(WALLET);
        uint256 r1 = policy.checkUserOpPolicy(policyId(), validUserOp());
        uint256 r2 = policy.checkUserOpPolicy(policyId(), validUserOp());
        uint256 r3 = policy.checkUserOpPolicy(policyId(), validUserOp());
        vm.stopPrank();

        assertEq(r1, SIG_VALIDATION_SUCCESS_UINT, "op1 should pass");
        assertEq(r2, SIG_VALIDATION_SUCCESS_UINT, "op2 should pass");
        assertEq(r3, SIG_VALIDATION_SUCCESS_UINT, "op3 should pass");

        (uint128 remaining,,) = policy.gasPolicyConfig(policyId(), WALLET);
        assertEq(remaining, ALLOWED - 3 * costPerOp, "allowed should reflect cumulative spend");
    }

    function test_checkUserOpPolicy_MultipleOps_ShouldFailOnceBudgetExhausted() public {
        // Install with a budget that allows exactly 2 ops of 200 each, third must fail
        GasPolicy policy = GasPolicy(address(module));
        uint128 twoOpsBudget = 400;
        vm.prank(WALLET);
        policy.onInstall(abi.encodePacked(policyId(), _installDataWithPaymaster(twoOpsBudget, false, address(0))));

        vm.startPrank(WALLET);
        uint256 r1 = policy.checkUserOpPolicy(policyId(), validUserOp());
        uint256 r2 = policy.checkUserOpPolicy(policyId(), validUserOp());
        uint256 r3 = policy.checkUserOpPolicy(policyId(), validUserOp());
        vm.stopPrank();

        assertEq(r1, SIG_VALIDATION_SUCCESS_UINT, "op1 should pass");
        assertEq(r2, SIG_VALIDATION_SUCCESS_UINT, "op2 should pass");
        assertEq(r3, SIG_VALIDATION_FAILED_UINT, "op3 should fail, budget exhausted");

        (uint128 remaining,,) = policy.gasPolicyConfig(policyId(), WALLET);
        assertEq(remaining, 0, "remaining budget should be exactly 0 after 2 successful ops");
    }

    // ---------------------------------------------------------------------
    // checkUserOpPolicy - paymaster enforcement branches
    // ---------------------------------------------------------------------

    function test_checkUserOpPolicy_WhenPaymasterEnforcedAndMatches_ShouldPass() public {
        GasPolicy policy = GasPolicy(address(module));
        vm.prank(WALLET);
        policy.onInstall(abi.encodePacked(policyId(), _installDataWithPaymaster(ALLOWED, true, paymaster)));

        bytes memory paymasterAndData = abi.encodePacked(paymaster, uint256(0), uint256(0));
        PackedUserOperation memory userOp = _userOp(VALID_GAS_LIMIT, VALID_FEE, paymasterAndData);

        vm.prank(WALLET);
        uint256 result = policy.checkUserOpPolicy(policyId(), userOp);

        assertEq(result, SIG_VALIDATION_SUCCESS_UINT, "matching paymaster should pass");
    }

    function test_checkUserOpPolicy_WhenPaymasterEnforcedAndMismatches_ShouldFail() public {
        GasPolicy policy = GasPolicy(address(module));
        vm.prank(WALLET);
        policy.onInstall(abi.encodePacked(policyId(), _installDataWithPaymaster(ALLOWED, true, paymaster)));

        bytes memory paymasterAndData = abi.encodePacked(otherPaymaster, uint256(0), uint256(0));
        PackedUserOperation memory userOp = _userOp(VALID_GAS_LIMIT, VALID_FEE, paymasterAndData);

        vm.prank(WALLET);
        uint256 result = policy.checkUserOpPolicy(policyId(), userOp);

        assertEq(result, SIG_VALIDATION_FAILED_UINT, "mismatched paymaster should fail");

        (uint128 remaining,,) = policy.gasPolicyConfig(policyId(), WALLET);
        assertEq(remaining, ALLOWED, "allowed should not be decremented on paymaster mismatch");
    }

    function test_checkUserOpPolicy_WhenPaymasterEnforcedButAllowedPaymasterIsZero_ShouldSkipCheckAndPass() public {
        // enforcePaymaster = true but allowedPaymaster == address(0) => the address(0) branch
        // short-circuits the paymaster comparison entirely, regardless of who the actual paymaster is.
        GasPolicy policy = GasPolicy(address(module));
        vm.prank(WALLET);
        policy.onInstall(abi.encodePacked(policyId(), _installDataWithPaymaster(ALLOWED, true, address(0))));

        bytes memory paymasterAndData = abi.encodePacked(otherPaymaster, uint256(0), uint256(0));
        PackedUserOperation memory userOp = _userOp(VALID_GAS_LIMIT, VALID_FEE, paymasterAndData);

        vm.prank(WALLET);
        uint256 result = policy.checkUserOpPolicy(policyId(), userOp);

        assertEq(result, SIG_VALIDATION_SUCCESS_UINT, "zero allowedPaymaster should skip paymaster check");
    }

    function test_checkUserOpPolicy_WhenNotEnforcingPaymaster_ShouldIgnorePaymasterAndDataField() public {
        // enforcePaymaster = false entirely skips the outer branch, even with empty paymasterAndData.
        GasPolicy policy = GasPolicy(address(module));
        vm.prank(WALLET);
        policy.onInstall(abi.encodePacked(policyId(), installData())); // enforcePaymaster = false

        vm.prank(WALLET);
        uint256 result = policy.checkUserOpPolicy(policyId(), validUserOp()); // empty paymasterAndData

        assertEq(result, SIG_VALIDATION_SUCCESS_UINT, "no paymaster enforcement should ignore paymasterAndData");
    }

    /// @notice When enforcePaymaster is true and allowedPaymaster != address(0), the
    /// length of paymasterAndData is guarded before slicing. Empty paymasterAndData does not
    /// revert with an out-of-bounds panic — it is treated as "no paymaster provided" and fails
    /// validation cleanly via SIG_VALIDATION_FAILED_UINT.
    function test_DO01_PaymasterEnforcedEmptyData_ReturnsFailed() public {
        GasPolicy policy = GasPolicy(address(module));
        vm.prank(WALLET);
        policy.onInstall(abi.encodePacked(policyId(), _installDataWithPaymaster(ALLOWED, true, paymaster)));

        PackedUserOperation memory userOp = _userOp(VALID_GAS_LIMIT, VALID_FEE, ""); // empty paymasterAndData

        vm.prank(WALLET);
        uint256 result = policy.checkUserOpPolicy(policyId(), userOp);

        assertEq(result, SIG_VALIDATION_FAILED_UINT, "empty paymasterAndData should fail cleanly, not revert");

        (uint128 remaining,,) = policy.gasPolicyConfig(policyId(), WALLET);
        assertEq(remaining, ALLOWED, "allowed should not be decremented on paymaster length-guard failure");
    }

    /// @notice paymasterAndData shorter than 20 bytes (but non-empty) is also guarded.
    function test_DO01_PaymasterEnforcedShortData_ReturnsFailed() public {
        GasPolicy policy = GasPolicy(address(module));
        vm.prank(WALLET);
        policy.onInstall(abi.encodePacked(policyId(), _installDataWithPaymaster(ALLOWED, true, paymaster)));

        PackedUserOperation memory userOp = _userOp(VALID_GAS_LIMIT, VALID_FEE, hex"1234"); // 2 bytes, < 20

        vm.prank(WALLET);
        uint256 result = policy.checkUserOpPolicy(policyId(), userOp);

        assertEq(result, SIG_VALIDATION_FAILED_UINT, "short paymasterAndData should fail cleanly, not revert");
    }

    /// @notice True uint256 cost is exactly 2^128 (>= budget of 1e18) but its
    /// low-128-bit residue is 0. A `uint128(allowed) >= uint128(maxAmount)`-style
    /// truncated comparison would let a residue of 0 slip under any nonzero budget. Comparing
    /// the full uint256 product against `allowed` means this op must be rejected and the
    /// budget must be left untouched.
    function test_TF01_TruncatedProductWithZeroResidue_ReturnsFailedAndBudgetUnchanged() public {
        GasPolicy policy = GasPolicy(address(module));
        uint128 allowed = 1e18;
        vm.prank(WALLET);
        policy.onInstall(abi.encodePacked(policyId(), _installDataWithPaymaster(allowed, false, address(0))));

        // verificationGasLimit = 2^80, callGasLimit = 0, preVerificationGas = 0, maxFeePerGas = 2^48
        // true product = 2^80 * 2^48 = 2^128 (low 128 bits == 0, so a uint128 truncation would see 0).
        uint128 verificationGasLimit = uint128(2 ** 80);
        uint128 callGasLimit = 0;
        uint128 maxFeePerGas = uint128(2 ** 48);
        PackedUserOperation memory userOp = _userOpRaw(verificationGasLimit, callGasLimit, 0, maxFeePerGas, "");

        // Sanity: confirm the residue really is 0 and the true cost really exceeds the budget.
        uint256 trueCost = (uint256(0) + verificationGasLimit + callGasLimit) * maxFeePerGas;
        assertEq(trueCost, 2 ** 128, "true cost should be exactly 2^128");
        assertEq(uint128(trueCost), 0, "low-128 residue should be 0 (this is what pre-fix code would compare)");
        assertGt(trueCost, allowed, "true cost must exceed the budget");

        vm.prank(WALLET);
        uint256 result = policy.checkUserOpPolicy(policyId(), userOp);

        assertEq(result, SIG_VALIDATION_FAILED_UINT, "over-cap op must fail despite zero low-128 residue");

        (uint128 remaining,,) = policy.gasPolicyConfig(policyId(), WALLET);
        assertEq(remaining, allowed, "budget must not be decremented when the true cost exceeds it");
    }

    // ---------------------------------------------------------------------
    // checkSignaturePolicy
    // ---------------------------------------------------------------------

    function test_checkSignaturePolicy_WhenNotLive_ShouldRevert() public {
        GasPolicy policy = GasPolicy(address(module));
        vm.prank(WALLET);
        vm.expectRevert();
        policy.checkSignaturePolicy(policyId(), WALLET, keccak256("hash"), "");
    }

    function test_checkSignaturePolicy_WhenLive_ShouldReturnSuccess() public {
        GasPolicy policy = GasPolicy(address(module));
        vm.prank(WALLET);
        policy.onInstall(abi.encodePacked(policyId(), installData()));

        vm.prank(WALLET);
        uint256 result = policy.checkSignaturePolicy(policyId(), WALLET, keccak256("hash"), "");

        assertEq(result, SIG_VALIDATION_SUCCESS_UINT, "should succeed when Live");
    }
}
