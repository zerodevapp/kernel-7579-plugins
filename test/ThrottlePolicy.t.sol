pragma solidity ^0.8.20;

import {PolicyTestBase} from "./base/PolicyTestBase.sol";
import {ThrottlePolicy, Status} from "src/policies/ThrottlePolicy.sol";
import {ValidAfter} from "src/types/Types.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IModule} from "src/interfaces/IERC7579Modules.sol";
import {SIG_VALIDATION_SUCCESS_UINT, SIG_VALIDATION_FAILED_UINT} from "src/types/Constants.sol";

contract ThrottlePolicyTest is PolicyTestBase {
    uint48 constant INTERVAL = 100;
    uint48 constant COUNT = 3;
    uint48 constant START_AT = 1000;

    ThrottlePolicy policy;

    function deployModule() internal virtual override returns (IModule) {
        policy = new ThrottlePolicy();
        return policy;
    }

    function _initializeTest() internal override {}

    function installData() internal view override returns (bytes memory) {
        return abi.encodePacked(bytes6(INTERVAL), bytes6(COUNT), bytes6(START_AT));
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
        (uint48 interval, uint48 count, ValidAfter startAt) = policy.throttleConfigs(id, WALLET);
        assertEq(interval, INTERVAL, "interval mismatch");
        assertEq(count, COUNT, "count mismatch");
        assertEq(ValidAfter.unwrap(startAt), START_AT, "startAt mismatch");
    }

    function _afterUninstallCheck(bytes32 id) internal virtual override {
        assertEq(
            uint8(policy.status(id, WALLET)), uint8(Status.Deprecated), "status should be Deprecated after uninstall"
        );
    }

    // checkUserOpPolicy returns a nonzero packed validAfter on success (never
    // SIG_VALIDATION_SUCCESS_UINT == 0), so the base "success" test's `assertEq(result, 0)` does
    // not hold. Override with an assertion of the real success shape.
    function testPolicyAfterInstallCheckUserOpPolicySuccess() public payable override {
        bytes32 id = policyId();
        vm.startPrank(WALLET);
        policy.onInstall(abi.encodePacked(id, installData()));

        uint256 validationResult = policy.checkUserOpPolicy(id, validUserOp());
        vm.stopPrank();
        assertFalse(validationResult == 0, "success returns a nonzero packed validAfter");
    }

    // ThrottlePolicy's checkUserOpPolicy does not fail on userOp shape — the base fail-test
    // (asserting a non-zero return for `invalidUserOp`) does not model this contract's real
    // failure mode. Override with the real exhausted-budget failure path (returns 1, not revert).
    function testPolicyAfterInstallCheckUserOpPolicyFail() public payable override {
        bytes32 id = policyId();
        vm.startPrank(WALLET);
        policy.onInstall(abi.encodePacked(id, installData()));

        PackedUserOperation memory userOp = _dummyUserOp();
        for (uint256 i = 0; i < COUNT; i++) {
            policy.checkUserOpPolicy(id, userOp);
        }
        uint256 result = policy.checkUserOpPolicy(id, userOp);
        vm.stopPrank();
        assertEq(result, SIG_VALIDATION_FAILED_UINT, "should return failure once count is exhausted");
    }

    // checkSignaturePolicy returns SIG_VALIDATION_SUCCESS_UINT unconditionally once Live (see
    // ThrottlePolicy.checkSignaturePolicy) — there is no signature-shape based failure to model
    // with a valid/invalid signature pair, so the base "fail" test's premise does not apply.
    // Override to assert the real, unconditional-success-when-Live behavior instead.
    function testPolicyCheckSignaturePolicyFail() public payable override {
        bytes32 id = policyId();
        vm.startPrank(WALLET);
        policy.onInstall(abi.encodePacked(id, installData()));

        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));
        (address sender, bytes memory sigData) = invalidSignatureData(testHash);

        uint256 result = policy.checkSignaturePolicy(id, sender, testHash, sigData);
        vm.stopPrank();
        assertEq(result, SIG_VALIDATION_SUCCESS_UINT, "checkSignaturePolicy always succeeds when Live");
    }

    function test_onInstall_SetsConfigAndStatus() public {
        bytes32 id = policyId();
        vm.prank(WALLET);
        policy.onInstall(abi.encodePacked(id, installData()));
        _afterInstallCheck(id);
    }

    function test_onInstall_RevertWhen_AlreadyLive() public {
        bytes32 id = policyId();
        vm.startPrank(WALLET);
        policy.onInstall(abi.encodePacked(id, installData()));
        vm.expectRevert();
        policy.onInstall(abi.encodePacked(id, installData()));
        vm.stopPrank();
    }

    function test_onInstall_RevertWhen_Deprecated() public {
        bytes32 id = policyId();
        vm.startPrank(WALLET);
        policy.onInstall(abi.encodePacked(id, installData()));
        policy.onUninstall(abi.encodePacked(id, installData()));
        assertEq(uint8(policy.status(id, WALLET)), uint8(Status.Deprecated), "should be Deprecated");

        // Status.NA is required for install; Deprecated is not NA, so re-install must revert.
        vm.expectRevert();
        policy.onInstall(abi.encodePacked(id, installData()));
        vm.stopPrank();
    }

    function test_onUninstall_RevertWhen_NotLive() public {
        bytes32 id = policyId();
        vm.prank(WALLET);
        vm.expectRevert();
        policy.onUninstall(abi.encodePacked(id, installData()));
    }

    function test_checkUserOpPolicy_RevertWhen_NotLive() public {
        bytes32 id = policyId();
        vm.prank(WALLET);
        vm.expectRevert();
        policy.checkUserOpPolicy(id, _dummyUserOp());
    }

    function test_checkUserOpPolicy_DecrementsCountAndAdvancesStartAt() public {
        bytes32 id = policyId();
        vm.startPrank(WALLET);
        policy.onInstall(abi.encodePacked(id, installData()));

        uint256 validationData = policy.checkUserOpPolicy(id, _dummyUserOp());
        vm.stopPrank();

        (, uint48 count, ValidAfter startAt) = policy.throttleConfigs(id, WALLET);
        assertEq(count, COUNT - 1, "count should decrement by 1");
        assertEq(ValidAfter.unwrap(startAt), START_AT + INTERVAL, "startAt should advance by interval");

        // Returned validAfter must be the PRE-increment startAt, validUntil must be 0.
        uint48 returnedValidAfter = uint48(validationData >> 208);
        uint48 returnedValidUntil = uint48(validationData >> 160);
        assertEq(returnedValidAfter, START_AT, "returned validAfter should be pre-increment startAt");
        assertEq(returnedValidUntil, 0, "returned validUntil should always be 0");
    }

    function test_checkUserOpPolicy_SuccessiveCallsAdvanceStartAtEachTime() public {
        bytes32 id = policyId();
        vm.startPrank(WALLET);
        policy.onInstall(abi.encodePacked(id, installData()));

        PackedUserOperation memory userOp = _dummyUserOp();

        uint256 v1 = policy.checkUserOpPolicy(id, userOp);
        uint48 validAfter1 = uint48(v1 >> 208);
        assertEq(validAfter1, START_AT, "first call returns original startAt");

        uint256 v2 = policy.checkUserOpPolicy(id, userOp);
        uint48 validAfter2 = uint48(v2 >> 208);
        assertEq(validAfter2, START_AT + INTERVAL, "second call returns startAt advanced by one interval");

        uint256 v3 = policy.checkUserOpPolicy(id, userOp);
        uint48 validAfter3 = uint48(v3 >> 208);
        assertEq(validAfter3, START_AT + 2 * INTERVAL, "third call returns startAt advanced by two intervals");

        (, uint48 count,) = policy.throttleConfigs(id, WALLET);
        assertEq(count, 0, "count should be fully exhausted after COUNT calls");
        vm.stopPrank();
    }

    function test_checkUserOpPolicy_ReturnsFailureWhenCountExhausted() public {
        bytes32 id = policyId();
        vm.startPrank(WALLET);
        policy.onInstall(abi.encodePacked(id, installData()));

        PackedUserOperation memory userOp = _dummyUserOp();
        for (uint256 i = 0; i < COUNT; i++) {
            policy.checkUserOpPolicy(id, userOp);
        }

        (, uint48 countBefore, ValidAfter startAtBefore) = policy.throttleConfigs(id, WALLET);
        assertEq(countBefore, 0, "count should be 0 before the exhausted call");

        uint256 result = policy.checkUserOpPolicy(id, userOp);
        assertEq(result, SIG_VALIDATION_FAILED_UINT, "should return SIG_VALIDATION_FAILED_UINT when count is 0");

        // Exhausted path must not mutate config further.
        (, uint48 countAfter, ValidAfter startAtAfter) = policy.throttleConfigs(id, WALLET);
        assertEq(countAfter, 0, "count should remain 0");
        assertEq(
            ValidAfter.unwrap(startAtAfter),
            ValidAfter.unwrap(startAtBefore),
            "startAt should not advance when exhausted"
        );
        vm.stopPrank();
    }

    /// @notice After an idle period the next slot is anchored to `now`, not to
    /// the stale `startAt`, so a burst of ops cannot all become immediately valid. With
    /// interval=1 day, count=3, startAt=t0, warping to t0+3days and calling once must push the
    /// stored startAt to `now + interval` (future), so an immediate second call in the same block
    /// returns a validAfter that is still in the future -- the count budget (3) is unaffected.
    function test_TF02_NoBurstAfterIdle() public {
        bytes32 id = policyId();
        uint48 interval = 1 days;
        uint48 count = 3;
        uint48 t0 = 1000;
        bytes memory data = abi.encodePacked(bytes6(interval), bytes6(count), bytes6(t0));

        vm.prank(WALLET);
        policy.onInstall(abi.encodePacked(id, data));

        uint256 idleUntil = uint256(t0) + 3 * uint256(interval);
        vm.warp(idleUntil);

        PackedUserOperation memory userOp = _dummyUserOp();

        vm.prank(WALLET);
        uint256 v1 = policy.checkUserOpPolicy(id, userOp);
        uint48 validAfter1 = uint48(v1 >> 208);
        assertEq(validAfter1, t0, "first post-idle call returns the pre-update (already-elapsed) startAt");
        assertLe(validAfter1, uint48(block.timestamp), "returned validAfter for this op should already be elapsed");

        // Stored startAt must now be anchored to `now`, not to the stale t0 + interval.
        (, uint48 countAfter1, ValidAfter storedStartAt1) = policy.throttleConfigs(id, WALLET);
        assertEq(
            ValidAfter.unwrap(storedStartAt1),
            uint48(idleUntil) + interval,
            "stored startAt should be anchored to now + interval, not t0 + interval"
        );
        assertEq(countAfter1, count - 1, "count should decrement by 1");

        // A second op in the same block must NOT be immediately valid -- its validAfter is future.
        vm.prank(WALLET);
        uint256 v2 = policy.checkUserOpPolicy(id, userOp);
        uint48 validAfter2 = uint48(v2 >> 208);
        assertEq(validAfter2, uint48(idleUntil) + interval, "second call's validAfter should be the anchored slot");
        assertGt(validAfter2, uint48(block.timestamp), "second call's validAfter must be in the future (no burst)");

        (, uint48 countAfter2,) = policy.throttleConfigs(id, WALLET);
        assertEq(countAfter2, count - 2, "count budget still tracks total ops, independent of anchoring");
    }

    function test_checkSignaturePolicy_RevertWhen_NotLive() public {
        vm.expectRevert();
        policy.checkSignaturePolicy(policyId(), WALLET, keccak256("hash"), "");
    }

    function test_checkSignaturePolicy_ReturnsSuccessWhenLive() public {
        bytes32 id = policyId();
        vm.startPrank(WALLET);
        policy.onInstall(abi.encodePacked(id, installData()));

        uint256 result = policy.checkSignaturePolicy(id, WALLET, keccak256("hash"), "");
        vm.stopPrank();
        assertEq(result, SIG_VALIDATION_SUCCESS_UINT, "checkSignaturePolicy should succeed when Live");
    }
}
