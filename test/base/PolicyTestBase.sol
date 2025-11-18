pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {IPolicy} from "src/interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {ModuleTestBase} from "./ModuleTestBase.sol";
import {MODULE_TYPE_POLICY} from "src/types/Constants.sol";

abstract contract PolicyTestBase is ModuleTestBase {
    function policyId() internal view virtual returns (bytes32) {
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

    function _afterInstallCheck(bytes32 id) internal virtual {}

    function _afterUninstallCheck(bytes32 id) internal virtual {}

    function testPolicyOnInstall() public payable {
        IPolicy policyModule = IPolicy(address(module));
        vm.startPrank(WALLET);
        policyModule.onInstall(abi.encodePacked(policyId(), installData()));
        vm.stopPrank();
        _afterInstallCheck(policyId());
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
        bytes32 policyId2 = keccak256(abi.encodePacked("POLICY_ID_2"));
        policyModule.onInstall(abi.encodePacked(policyId2, installData()));
        vm.stopPrank();
        _afterInstallCheck(policyId());
        _afterInstallCheck(policyId2);
    }

    function testPolicyOnUninstall() public payable {
        IPolicy policyModule = IPolicy(address(module));
        vm.startPrank(WALLET);
        policyModule.onInstall(abi.encodePacked(policyId(), installData()));
        _afterInstallCheck(policyId());

        policyModule.onUninstall(abi.encodePacked(policyId(), installData()));
        _afterUninstallCheck(policyId());
        vm.stopPrank();
    }

    function testPolicyAfterInstallCheckUserOpPolicySuccess() public payable virtual {
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

    function testPolicyAfterInstallCheckUserOpPolicyFail() public payable virtual {
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

    function testPolicyCheckSignaturePolicyFail() public payable virtual {
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
