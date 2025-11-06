pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {IPolicy} from "src/interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {ModuleTestBase} from "./ModuleTestBase.sol";
import {MODULE_TYPE_POLICY} from "src/types/Constants.sol";

abstract contract PolicyTestBase is ModuleTestBase {
    function policyId() internal view virtual returns(bytes32) {
        return keccak256(abi.encodePacked("POLICY_ID_1"));
    }

    function validUserOp() internal view virtual returns (PackedUserOperation memory);

    function invalidUserOp() internal view virtual returns (PackedUserOperation memory);

    function validSignatureData(bytes32 hash) internal view virtual returns (address sender, bytes memory signature);

    function invalidSignatureData(bytes32 hash) internal view virtual returns (address sender, bytes memory signature);

    function testModuleTypePolicy() public view {
        IPolicy policyModule = IPolicy(address(module));
        bool result = policyModule.isModuleType(MODULE_TYPE_POLICY);
        assertTrue(result);
    }

    function testPolicyOnInstall() public payable {
        IPolicy policyModule = IPolicy(address(module));
        bool initializedBefore = policyModule.isInitialized(WALLET);
        assertEq(initializedBefore, false);
        vm.startPrank(WALLET);
        policyModule.onInstall(abi.encodePacked(policyId(), installData()));
        vm.stopPrank();
        bool initializedAfter = policyModule.isInitialized(WALLET);
        assertEq(initializedAfter, true);
    }

    function testPolicyOnInstallFailSameId() public payable {
        IPolicy policyModule = IPolicy(address(module));
        vm.startPrank(WALLET);
        policyModule.onInstall(abi.encodePacked(policyId(), installData()));
        vm.expectRevert();
        policyModule.onInstall(abi.encodePacked(policyId(), installData()));
        vm.stopPrank();
    }

    function testPolicyOnInstallMultipleTimesSuccess() public payable {
        IPolicy policyModule = IPolicy(address(module));
        vm.startPrank(WALLET);
        policyModule.onInstall(abi.encodePacked(policyId(), installData()));
        policyModule.onInstall(abi.encodePacked(keccak256(abi.encodePacked("POLICY_ID_2")), installData()));
        vm.stopPrank();
        bool initializedAfter = policyModule.isInitialized(WALLET);
        assertEq(initializedAfter, true);
    }

    function testPolicyOnUninstall() public payable {
        IPolicy policyModule = IPolicy(address(module));
        vm.startPrank(WALLET);
        policyModule.onInstall(abi.encodePacked(policyId(), installData()));
        bool initializedAfterInstall = policyModule.isInitialized(WALLET);
        assertEq(initializedAfterInstall, true);

        policyModule.onUninstall(abi.encodePacked(policyId(), installData()));
        bool initializedAfterUninstall = policyModule.isInitialized(WALLET);
        assertEq(initializedAfterUninstall, false);
        vm.stopPrank();
    }

    function testPolicyAfterInstallCheckUserOpPolicySuccess() public payable {
        IPolicy policyModule = IPolicy(address(module));
        vm.startPrank(WALLET);
        policyModule.onInstall(abi.encodePacked(policyId(), installData()));
        vm.stopPrank();

        PackedUserOperation memory userOp = validUserOp();

        vm.startPrank(WALLET);
        uint256 validationResult = policyModule.checkUserOpPolicy(policyId(), userOp);
        vm.stopPrank();
        assertEq(validationResult, 0);
    }

    function testPolicyAfterInstallCheckUserOpPolicyFail() public payable {
        IPolicy policyModule = IPolicy(address(module));
        vm.startPrank(WALLET);
        policyModule.onInstall(abi.encodePacked(policyId(), installData()));
        vm.stopPrank();

        PackedUserOperation memory userOp = invalidUserOp();

        vm.startPrank(WALLET);
        uint256 validationResult = policyModule.checkUserOpPolicy(policyId(), userOp);
        vm.stopPrank();
        assertFalse(validationResult == 0);
    }

    function testPolicyCheckSignaturePolicySuccess() public payable {
        IPolicy policyModule = IPolicy(address(module));
        vm.startPrank(WALLET);
        policyModule.onInstall(abi.encodePacked(policyId(), installData()));
        vm.stopPrank();

        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));
        (address sender, bytes memory sigData) = validSignatureData(testHash);

        vm.startPrank(WALLET);
        uint256 result = policyModule.checkSignaturePolicy(policyId(), sender, testHash, sigData);
        vm.stopPrank();
        assertEq(result, 0);
    }

    function testPolicyCheckSignaturePolicyFail() public payable {
        IPolicy policyModule = IPolicy(address(module));
        vm.startPrank(WALLET);
        policyModule.onInstall(abi.encodePacked(policyId(), installData()));
        vm.stopPrank();

        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));
        (address sender, bytes memory sigData) = invalidSignatureData(testHash);

        vm.startPrank(WALLET);
        uint256 result = policyModule.checkSignaturePolicy(policyId(), sender, testHash, sigData);
        vm.stopPrank();
        assertFalse(result == 0);
    }
}
