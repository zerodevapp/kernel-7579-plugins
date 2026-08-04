pragma solidity ^0.8.20;

import {PolicyTestBase} from "./base/PolicyTestBase.sol";
import {RateLimitPolicy, Status} from "src/policies/RateLimitPolicy.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IModule} from "src/interfaces/IERC7579Modules.sol";
import {SIG_VALIDATION_SUCCESS_UINT} from "src/types/Constants.sol";

contract RateLimitPolicyTest is PolicyTestBase {
    uint48 constant INTERVAL = 100;
    uint48 constant INITIAL_COUNT = 3;

    RateLimitPolicy policy;

    function deployModule() internal virtual override returns (IModule) {
        policy = new RateLimitPolicy();
        return policy;
    }

    function _initializeTest() internal override {}

    function installData() internal view override returns (bytes memory) {
        return abi.encodePacked(bytes6(INTERVAL), bytes6(INITIAL_COUNT));
    }

    function _dummyUserOp() internal view returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: WALLET,
            nonce: 0,
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(abi.encodePacked(uint128(100000), uint128(200000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: "",
            signature: ""
        });
    }

    function validUserOp() internal view virtual override returns (PackedUserOperation memory) {
        return _dummyUserOp();
    }

    function invalidUserOp() internal view virtual override returns (PackedUserOperation memory) {
        return _dummyUserOp();
    }

    function validSignatureData(bytes32) internal view virtual override returns (address, bytes memory) {
        return (WALLET, "");
    }

    function invalidSignatureData(bytes32) internal view virtual override returns (address, bytes memory) {
        return (WALLET, "");
    }

    function _afterInstallCheck(bytes32 id) internal virtual override {
        assertEq(uint8(policy.status(id, WALLET)), uint8(Status.Live), "status should be Live after install");
        (uint48 interval, uint48 initialCount) = policy.rateLimitConfigs(id, WALLET);
        assertEq(interval, INTERVAL, "interval mismatch");
        assertEq(initialCount, INITIAL_COUNT, "initialCount mismatch");
        (uint48 storedCount, uint48 resetDate) = policy.rateLimitState(id, WALLET);
        assertEq(storedCount, INITIAL_COUNT, "storedCount should start at initialCount");
        assertEq(resetDate, uint48(block.timestamp) + INTERVAL, "resetDate should be now + interval");
    }

    function _afterUninstallCheck(bytes32 id) internal virtual override {
        assertEq(
            uint8(policy.status(id, WALLET)), uint8(Status.Deprecated), "status should be Deprecated after uninstall"
        );
    }

    // checkUserOpPolicy always returns a non-zero packed validation timestamp on success (never
    // SIG_VALIDATION_SUCCESS_UINT == 0), so the base "success" test's `assertEq(result, 0)` does
    // not hold for this policy. Override with an assertion of the real success shape.
    function testPolicyAfterInstallCheckUserOpPolicySuccess() public payable override {
        bytes32 id = policyId();
        vm.startPrank(WALLET);
        policy.onInstall(abi.encodePacked(id, installData()));

        uint256 validationResult = policy.checkUserOpPolicy(id, validUserOp());
        vm.stopPrank();
        assertFalse(validationResult == 0, "success returns a nonzero packed validAfter/validUntil");
    }

    // checkUserOpPolicy does not gate on Status.Live, so the base "fail" test (which asserts a
    // non-zero return for `invalidUserOp`) does not apply here — there is no userOp-shape based
    // failure. Override with a revert-based assertion of the real failure mode: RateLimited().
    function testPolicyAfterInstallCheckUserOpPolicyFail() public payable override {
        bytes32 id = policyId();
        vm.startPrank(WALLET);
        policy.onInstall(abi.encodePacked(id, installData()));

        PackedUserOperation memory userOp = _dummyUserOp();
        for (uint256 i = 0; i < INITIAL_COUNT; i++) {
            policy.checkUserOpPolicy(id, userOp);
        }

        vm.expectRevert(RateLimitPolicy.RateLimited.selector);
        policy.checkUserOpPolicy(id, userOp);
        vm.stopPrank();
    }

    // checkSignaturePolicy returns SIG_VALIDATION_SUCCESS_UINT unconditionally (see
    // RateLimitPolicy.checkSignaturePolicy) — there is no signature-shape based failure to
    // model, so the base "fail" test's premise (a distinguishable invalid signature) does not
    // apply. Override to assert the real, unconditional-success behavior instead.
    function testPolicyCheckSignaturePolicyFail() public payable override {
        bytes32 id = policyId();
        vm.startPrank(WALLET);
        policy.onInstall(abi.encodePacked(id, installData()));

        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));
        (address sender, bytes memory sigData) = invalidSignatureData(testHash);

        uint256 result = policy.checkSignaturePolicy(id, sender, testHash, sigData);
        vm.stopPrank();
        assertEq(result, SIG_VALIDATION_SUCCESS_UINT, "checkSignaturePolicy always succeeds, even for 'invalid' inputs");
    }

    function test_onInstall_RevertWhen_DataTooShort() public {
        bytes32 id = policyId();
        bytes memory shortData = abi.encodePacked(bytes6(INTERVAL), bytes5(uint40(1)));
        vm.prank(WALLET);
        vm.expectRevert(RateLimitPolicy.InvalidInstallData.selector);
        policy.onInstall(abi.encodePacked(id, shortData));
    }

    function test_onInstall_RevertWhen_ExactlyTooShort() public {
        // 11 bytes total is one short of the 12-byte minimum.
        bytes32 id = policyId();
        bytes memory shortData = new bytes(11);
        vm.prank(WALLET);
        vm.expectRevert(RateLimitPolicy.InvalidInstallData.selector);
        policy.onInstall(abi.encodePacked(id, shortData));
    }

    function test_onInstall_AllowsExtraTrailingBytes() public {
        // >= 12 bytes is accepted; extra bytes beyond the first 12 are ignored.
        bytes32 id = policyId();
        bytes memory data = abi.encodePacked(bytes6(INTERVAL), bytes6(INITIAL_COUNT), bytes1(0xAB));
        vm.prank(WALLET);
        policy.onInstall(abi.encodePacked(id, data));
        _afterInstallCheck(id);
    }

    function test_checkUserOpPolicy_DecrementsStoredCount() public {
        bytes32 id = policyId();
        vm.startPrank(WALLET);
        policy.onInstall(abi.encodePacked(id, installData()));

        PackedUserOperation memory userOp = _dummyUserOp();
        policy.checkUserOpPolicy(id, userOp);
        (uint48 storedCount,) = policy.rateLimitState(id, WALLET);
        assertEq(storedCount, INITIAL_COUNT - 1, "storedCount should decrement by 1");
        vm.stopPrank();
    }

    function test_checkUserOpPolicy_ReturnsPackedValidationData() public {
        bytes32 id = policyId();
        vm.startPrank(WALLET);
        policy.onInstall(abi.encodePacked(id, installData()));

        uint256 expectedResetDate = block.timestamp + INTERVAL;
        uint256 validationData = policy.checkUserOpPolicy(id, _dummyUserOp());
        vm.stopPrank();

        uint48 validAfter = uint48(validationData >> 208);
        uint48 validUntil = uint48(validationData >> 160);
        assertEq(validAfter, uint48(block.timestamp), "validAfter should be current time");
        assertEq(validUntil, uint48(expectedResetDate), "validUntil should be resetDate");
    }

    function test_checkUserOpPolicy_RevertWhen_BudgetExhausted() public {
        bytes32 id = policyId();
        vm.startPrank(WALLET);
        policy.onInstall(abi.encodePacked(id, installData()));

        PackedUserOperation memory userOp = _dummyUserOp();
        for (uint256 i = 0; i < INITIAL_COUNT; i++) {
            policy.checkUserOpPolicy(id, userOp);
        }
        (uint48 storedCount,) = policy.rateLimitState(id, WALLET);
        assertEq(storedCount, 0, "storedCount should be exhausted");

        vm.expectRevert(RateLimitPolicy.RateLimited.selector);
        policy.checkUserOpPolicy(id, userOp);
        vm.stopPrank();
    }

    function test_checkUserOpPolicy_RefillsAfterWindowElapses() public {
        bytes32 id = policyId();
        vm.startPrank(WALLET);
        policy.onInstall(abi.encodePacked(id, installData()));

        PackedUserOperation memory userOp = _dummyUserOp();
        for (uint256 i = 0; i < INITIAL_COUNT; i++) {
            policy.checkUserOpPolicy(id, userOp);
        }
        vm.expectRevert(RateLimitPolicy.RateLimited.selector);
        policy.checkUserOpPolicy(id, userOp);

        // Warp past the reset window; budget should refill to initialCount and succeed again.
        vm.warp(block.timestamp + INTERVAL);
        uint256 validationData = policy.checkUserOpPolicy(id, userOp);
        vm.stopPrank();

        (uint48 storedCount, uint48 resetDate) = policy.rateLimitState(id, WALLET);
        // One op was consumed after the refill, so storedCount = initialCount - 1.
        assertEq(storedCount, INITIAL_COUNT - 1, "storedCount should refill then decrement");
        assertEq(resetDate, uint48(block.timestamp) + INTERVAL, "resetDate should be pushed forward");

        uint48 validAfter = uint48(validationData >> 208);
        uint48 validUntil = uint48(validationData >> 160);
        assertEq(validAfter, uint48(block.timestamp), "validAfter should be new current time");
        assertEq(validUntil, resetDate, "validUntil should be new resetDate");
    }

    function test_checkUserOpPolicy_RefillExactlyAtResetDate() public {
        // Boundary: block.timestamp == state.resetDate triggers the refill branch (>=).
        bytes32 id = policyId();
        vm.startPrank(WALLET);
        policy.onInstall(abi.encodePacked(id, installData()));
        (, uint48 resetDateBefore) = policy.rateLimitState(id, WALLET);

        vm.warp(resetDateBefore);
        policy.checkUserOpPolicy(id, _dummyUserOp());
        (uint48 storedCount,) = policy.rateLimitState(id, WALLET);
        // Refilled to INITIAL_COUNT then decremented once.
        assertEq(storedCount, INITIAL_COUNT - 1, "storedCount should refill exactly at resetDate boundary");
        vm.stopPrank();
    }

    function test_checkSignaturePolicy_AlwaysReturnsSuccess() public {
        bytes32 id = policyId();
        vm.prank(WALLET);
        policy.onInstall(abi.encodePacked(id, installData()));

        uint256 result = policy.checkSignaturePolicy(id, WALLET, keccak256("hash"), "");
        assertEq(result, SIG_VALIDATION_SUCCESS_UINT, "checkSignaturePolicy should always succeed");
    }

    function test_checkSignaturePolicy_ReturnsSuccessEvenWithoutInstall() public {
        // checkSignaturePolicy is unconditional and does not check status.
        uint256 result = policy.checkSignaturePolicy(policyId(), WALLET, keccak256("hash"), "");
        assertEq(result, SIG_VALIDATION_SUCCESS_UINT, "checkSignaturePolicy should succeed regardless of status");
    }

    function test_onInstall_RevertWhen_AlreadyLive() public {
        bytes32 id = policyId();
        vm.startPrank(WALLET);
        policy.onInstall(abi.encodePacked(id, installData()));
        vm.expectRevert();
        policy.onInstall(abi.encodePacked(id, installData()));
        vm.stopPrank();
    }

    function test_onInstall_AllowedAfterUninstall() public {
        bytes32 id = policyId();
        vm.startPrank(WALLET);
        policy.onInstall(abi.encodePacked(id, installData()));
        policy.onUninstall(abi.encodePacked(id, installData()));
        assertEq(uint8(policy.status(id, WALLET)), uint8(Status.Deprecated), "should be Deprecated");

        // Re-install allowed since status != Live.
        policy.onInstall(abi.encodePacked(id, installData()));
        assertEq(uint8(policy.status(id, WALLET)), uint8(Status.Live), "should be Live again after re-install");
        vm.stopPrank();
    }

    function test_onUninstall_RevertWhen_NotLive() public {
        bytes32 id = policyId();
        vm.prank(WALLET);
        vm.expectRevert();
        policy.onUninstall(abi.encodePacked(id, installData()));
    }
}
