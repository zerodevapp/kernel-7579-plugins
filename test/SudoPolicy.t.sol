pragma solidity ^0.8.20;

import {PolicyTestBase} from "./base/PolicyTestBase.sol";
import {SudoPolicy} from "src/policies/SudoPolicy.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IModule, IPolicy} from "src/interfaces/IERC7579Modules.sol";
import {SIG_VALIDATION_SUCCESS_UINT} from "src/types/Constants.sol";

contract SudoPolicyTest is PolicyTestBase {
    function deployModule() internal virtual override returns (IModule) {
        return new SudoPolicy();
    }

    function _initializeTest() internal override {}

    function installData() internal view virtual override returns (bytes memory) {
        return "";
    }

    function validUserOp() internal view virtual override returns (PackedUserOperation memory) {
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

    function invalidUserOp() internal view virtual override returns (PackedUserOperation memory) {
        // SudoPolicy has no fail path; kept for interface parity only.
        return validUserOp();
    }

    function validSignatureData(bytes32)
        internal
        view
        virtual
        override
        returns (address sender, bytes memory signature)
    {
        return (WALLET, "");
    }

    function invalidSignatureData(bytes32)
        internal
        view
        virtual
        override
        returns (address sender, bytes memory signature)
    {
        // SudoPolicy has no fail path; kept for interface parity only.
        return (WALLET, "");
    }

    // SudoPolicy's onInstall is a true no-op (no stored state), so installing the same
    // policy id twice does NOT revert — unlike stateful policies (e.g. CallerPolicy) that
    // track an installed/live status per id. Override to assert the real no-op behavior
    // instead of the stateful-policy default inherited from PolicyTestBase.
    function testPolicyOnInstallFailSameId() public payable override {
        IPolicy policyModule = IPolicy(address(module));
        vm.startPrank(WALLET);
        policyModule.onInstall(abi.encodePacked(policyId(), installData()));
        // Second install with the same id must succeed silently since _policyOninstall is a no-op.
        policyModule.onInstall(abi.encodePacked(policyId(), installData()));
        vm.stopPrank();
    }

    // SudoPolicy always returns SIG_VALIDATION_SUCCESS_UINT regardless of userOp content —
    // there is no way to make checkUserOpPolicy fail, so override to assert the real spec.
    function testPolicyAfterInstallCheckUserOpPolicyFail() public payable override {
        IPolicy policyModule = IPolicy(address(module));
        vm.startPrank(WALLET);
        policyModule.onInstall(abi.encodePacked(policyId(), installData()));

        PackedUserOperation memory userOp = invalidUserOp();
        uint256 validationResult = policyModule.checkUserOpPolicy(policyId(), userOp);
        vm.stopPrank();
        assertEq(validationResult, SIG_VALIDATION_SUCCESS_UINT, "SudoPolicy must always approve userOps");
    }

    // Same reasoning for signature checks — SudoPolicy has no fail path.
    function testPolicyCheckSignaturePolicyFail() public payable override {
        IPolicy policyModule = IPolicy(address(module));
        vm.startPrank(WALLET);
        policyModule.onInstall(abi.encodePacked(policyId(), installData()));

        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));
        (address sender, bytes memory sigData) = invalidSignatureData(testHash);
        uint256 result = policyModule.checkSignaturePolicy(policyId(), sender, testHash, sigData);
        vm.stopPrank();
        assertEq(result, SIG_VALIDATION_SUCCESS_UINT, "SudoPolicy must always approve signatures");
    }

    // checkUserOpPolicy/checkSignaturePolicy must also succeed without any prior onInstall,
    // since SudoPolicy's approval does not depend on install state at all.
    function test_checkUserOpPolicy_WithoutInstall_StillSucceeds() public {
        IPolicy policyModule = IPolicy(address(module));
        PackedUserOperation memory userOp = validUserOp();

        uint256 result = policyModule.checkUserOpPolicy(policyId(), userOp);
        assertEq(result, SIG_VALIDATION_SUCCESS_UINT, "SudoPolicy should approve even without install");
    }

    function test_checkSignaturePolicy_WithoutInstall_StillSucceeds() public view {
        IPolicy policyModule = IPolicy(address(module));
        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));

        uint256 result = policyModule.checkSignaturePolicy(policyId(), WALLET, testHash, "");
        assertEq(result, SIG_VALIDATION_SUCCESS_UINT, "SudoPolicy should approve even without install");
    }

    // Ensure onInstall/onUninstall are true no-ops: calling with only the 32-byte id
    // (empty tail data) must not revert, covering the empty _policyOninstall/_policyOnUninstall bodies.
    function test_onInstall_WithEmptyData_DoesNotRevert() public {
        IPolicy policyModule = IPolicy(address(module));
        vm.prank(WALLET);
        policyModule.onInstall(abi.encodePacked(policyId()));
    }

    function test_onUninstall_WithEmptyData_DoesNotRevert() public {
        IPolicy policyModule = IPolicy(address(module));
        vm.startPrank(WALLET);
        policyModule.onInstall(abi.encodePacked(policyId()));
        policyModule.onUninstall(abi.encodePacked(policyId()));
        vm.stopPrank();
    }
}
