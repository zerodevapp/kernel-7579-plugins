pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {ISigner} from "src/interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {ModuleTestBase} from "./ModuleTestBase.sol";
import {MODULE_TYPE_SIGNER} from "src/types/Constants.sol";

abstract contract SignerTestBase is ModuleTestBase {
    function signerId() internal view virtual returns (bytes32) {
        return keccak256(abi.encodePacked("SIGNER_ID_1"));
    }

    function userOpSignature(PackedUserOperation memory userOp, bool valid) internal view virtual returns (bytes memory);

    function erc1271Signature(bytes32 hash, bool valid)
        internal
        view
        virtual
        returns (address sender, bytes memory signature);

    function testModuleTypeSigner() public view {
        ISigner signerModule = ISigner(address(module));
        bool result = signerModule.isModuleType(MODULE_TYPE_SIGNER); // 6 is the module type for Signer
        assertTrue(result);
    }

    function _afterInstallCheck(bytes32 id) internal virtual {
        ISigner signerModule = ISigner(address(module));
        bool initializedAfter = signerModule.isInitialized(WALLET);
        assertEq(initializedAfter, true);
    }

    function _afterUninstallCheck(bytes32 id) internal virtual {
        ISigner signerModule = ISigner(address(module));
        bool initializedAfterUninstall = signerModule.isInitialized(WALLET);
        assertEq(initializedAfterUninstall, false);
    }

    function testSignerOnInstall() public payable virtual {
        ISigner signerModule = ISigner(address(module));
        bool initializedBefore = signerModule.isInitialized(WALLET);
        assertEq(initializedBefore, false);
        vm.startPrank(WALLET);
        signerModule.onInstall(abi.encodePacked(signerId(), installData()));
        vm.stopPrank();
        _afterInstallCheck(signerId());
    }

    function testSignerOnInstallFailSameId() public payable {
        ISigner signerModule = ISigner(address(module));
        vm.startPrank(WALLET);
        signerModule.onInstall(abi.encodePacked(signerId(), installData()));
        vm.expectRevert();
        signerModule.onInstall(abi.encodePacked(signerId(), installData()));
        vm.stopPrank();
    }

    function testSignerOnInstallMultipleTimesSuccess() public payable virtual {
        ISigner signerModule = ISigner(address(module));
        vm.startPrank(WALLET);
        signerModule.onInstall(abi.encodePacked(signerId(), installData()));
        bytes32 signerId2 = keccak256(abi.encodePacked("SIGNER_ID_2"));
        signerModule.onInstall(abi.encodePacked(signerId2, installData()));
        vm.stopPrank();
        _afterInstallCheck(signerId());
        _afterInstallCheck(signerId2);
    }

    function testSignerOnUninstall() public payable virtual {
        ISigner signerModule = ISigner(address(module));
        vm.startPrank(WALLET);
        signerModule.onInstall(abi.encodePacked(signerId(), installData()));
        _afterInstallCheck(signerId());

        signerModule.onUninstall(abi.encodePacked(signerId(), installData()));
        _afterUninstallCheck(signerId());
        vm.stopPrank();
    }

    function testSignerAfterInstallValidateUserOpSignatureSuccess() public payable {
        ISigner signerModule = ISigner(address(module));
        vm.startPrank(WALLET);
        signerModule.onInstall(abi.encodePacked(signerId(), installData()));
        vm.stopPrank();

        // Further signature validation tests can be implemented here.
        PackedUserOperation memory userOp = PackedUserOperation({
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

        userOp.signature = userOpSignature(userOp, true);

        vm.startPrank(WALLET);
        uint256 validationResult =
            signerModule.checkUserOpSignature(signerId(), userOp, ENTRYPOINT.getUserOpHash(userOp));
        vm.stopPrank();
        assertEq(validationResult, 0);
    }

    function testSignerAfterInstallValidateUserOpSignatureFail() public payable {
        ISigner signerModule = ISigner(address(module));
        vm.startPrank(WALLET);
        signerModule.onInstall(abi.encodePacked(signerId(), installData()));
        vm.stopPrank();

        PackedUserOperation memory userOp = PackedUserOperation({
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

        // Intentionally provide an invalid signature
        userOp.signature = userOpSignature(userOp, false);

        vm.startPrank(WALLET);
        uint256 validationResult =
            signerModule.checkUserOpSignature(signerId(), userOp, ENTRYPOINT.getUserOpHash(userOp));
        vm.stopPrank();
        assertFalse(validationResult == 0);
    }

    function testSignerIsValidSignatureWithSenderSuccess() public payable {
        ISigner signerModule = ISigner(address(module));
        vm.startPrank(WALLET);
        signerModule.onInstall(abi.encodePacked(signerId(), installData()));
        vm.stopPrank();

        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));
        (address sender, bytes memory signature) = erc1271Signature(testHash, true);

        vm.startPrank(WALLET);
        bytes4 result = signerModule.checkSignature(signerId(), sender, testHash, signature);
        vm.stopPrank();
        assertTrue(result == 0x1626ba7e); // ERC1271_MAGICVALUE
    }

    function testSignerIsValidSignatureWithSenderFail() public payable {
        ISigner signerModule = ISigner(address(module));
        vm.startPrank(WALLET);
        signerModule.onInstall(abi.encodePacked(signerId(), installData()));
        vm.stopPrank();

        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));
        (address sender, bytes memory signature) = erc1271Signature(testHash, false);

        vm.startPrank(WALLET);
        bytes4 result = signerModule.checkSignature(signerId(), sender, testHash, signature);
        vm.stopPrank();
        assertFalse(result == 0x1626ba7e); // ERC1271_INVALID
    }
}
