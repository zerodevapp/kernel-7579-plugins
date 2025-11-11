pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {IValidator} from "src/interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {ModuleTestBase} from "./ModuleTestBase.sol";
import {MODULE_TYPE_VALIDATOR} from "src/types/Constants.sol";

abstract contract ValidatorTestBase is ModuleTestBase {
    function userOpSignature(PackedUserOperation memory userOp, bool valid) internal view virtual returns (bytes memory);

    function erc1271Signature(bytes32 hash, bool valid)
        internal
        view
        virtual
        returns (address sender, bytes memory signature);

    function testModuleTypeValidator() public view {
        IValidator validatorModule = IValidator(address(module));
        bool result = validatorModule.isModuleType(MODULE_TYPE_VALIDATOR);
        assertTrue(result);
    }

    function _afterInstallCheck() internal virtual {
        IValidator validatorModule = IValidator(address(module));
        bool initializedAfter = validatorModule.isInitialized(WALLET);
        assertEq(initializedAfter, true);
    }

    function _afterUninstallCheck() internal virtual {
        IValidator validatorModule = IValidator(address(module));
        bool initializedAfterUninstall = validatorModule.isInitialized(WALLET);
        assertEq(initializedAfterUninstall, false);
    }

    function testValidatorOnInstall() public payable {
        IValidator validatorModule = IValidator(address(module));
        bool initializedBefore = validatorModule.isInitialized(WALLET);
        assertEq(initializedBefore, false);
        vm.startPrank(WALLET);
        validatorModule.onInstall(installData());
        vm.stopPrank();
        _afterInstallCheck();
    }

    function testValidatorOnInstallFailIfAlreadyInitialized() public payable {
        IValidator validatorModule = IValidator(address(module));
        vm.startPrank(WALLET);
        validatorModule.onInstall(installData());
        vm.expectRevert();
        validatorModule.onInstall(installData());
        vm.stopPrank();
    }

    function testValidatorOnUninstall() public payable {
        IValidator validatorModule = IValidator(address(module));
        vm.startPrank(WALLET);
        validatorModule.onInstall(installData());
        _afterInstallCheck();

        validatorModule.onUninstall(installData());
        _afterUninstallCheck();
        vm.stopPrank();
    }

    function testValidatorAfterInstallValidateUserOpSuccess() public payable {
        IValidator validatorModule = IValidator(address(module));
        vm.startPrank(WALLET);
        validatorModule.onInstall(installData());
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

        userOp.signature = userOpSignature(userOp, true);

        vm.startPrank(WALLET);
        uint256 validationResult = validatorModule.validateUserOp(userOp, ENTRYPOINT.getUserOpHash(userOp));
        vm.stopPrank();
        assertEq(validationResult, 0);
    }

    function testValidatorAfterInstallValidateUserOpFail() public payable {
        IValidator validatorModule = IValidator(address(module));
        vm.startPrank(WALLET);
        validatorModule.onInstall(installData());
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
        uint256 validationResult = validatorModule.validateUserOp(userOp, ENTRYPOINT.getUserOpHash(userOp));
        vm.stopPrank();
        assertFalse(validationResult == 0);
    }

    function testValidatorIsValidSignatureWithSenderSuccess() public payable {
        IValidator validatorModule = IValidator(address(module));
        vm.startPrank(WALLET);
        validatorModule.onInstall(installData());
        vm.stopPrank();

        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));
        (address sender, bytes memory signature) = erc1271Signature(testHash, true);

        vm.startPrank(WALLET);
        bytes4 result = validatorModule.isValidSignatureWithSender(sender, testHash, signature);
        vm.stopPrank();
        assertTrue(result == 0x1626ba7e); // ERC1271_MAGICVALUE
    }

    function testValidatorIsValidSignatureWithSenderFail() public payable {
        IValidator validatorModule = IValidator(address(module));
        vm.startPrank(WALLET);
        validatorModule.onInstall(installData());
        vm.stopPrank();

        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));
        (address sender, bytes memory signature) = erc1271Signature(testHash, false);

        vm.startPrank(WALLET);
        bytes4 result = validatorModule.isValidSignatureWithSender(sender, testHash, signature);
        vm.stopPrank();
        assertFalse(result == 0x1626ba7e); // ERC1271_INVALID
    }
}
