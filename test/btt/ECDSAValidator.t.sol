// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {ECDSAValidator} from "src/validators/ECDSAValidator.sol";
import {IValidator, IHook, IModule} from "src/interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {
    SIG_VALIDATION_SUCCESS_UINT,
    SIG_VALIDATION_FAILED_UINT,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_HOOK,
    MODULE_TYPE_STATELESS_VALIDATOR,
    MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER,
    ERC1271_MAGICVALUE,
    ERC1271_INVALID
} from "src/types/Constants.sol";

contract ECDSAValidatorBTTTest is Test {
    ECDSAValidator public ecdsaValidator;
    IEntryPoint public ENTRYPOINT;

    address public owner;
    uint256 public ownerKey;
    address public wallet;

    event OwnerRegistered(address indexed kernel, address indexed owner);

    function setUp() public {
        ecdsaValidator = new ECDSAValidator();
        ENTRYPOINT = EntryPointLib.deploy();
        (owner, ownerKey) = makeAddrAndKey("owner");
        wallet = address(0x1234);
    }

    // ==================== Helper Functions ====================

    function _installValidator() internal {
        vm.prank(wallet);
        ecdsaValidator.onInstall(abi.encodePacked(owner));
    }

    function _createUserOp() internal view returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: wallet,
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

    function _signRawHash(bytes32 hash, uint256 privateKey) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hash);
        return abi.encodePacked(r, s, v);
    }

    function _signEthSignedMessageHash(bytes32 hash, uint256 privateKey) internal pure returns (bytes memory) {
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(hash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, ethHash);
        return abi.encodePacked(r, s, v);
    }

    // ==================== isModuleType Tests ====================

    function test_WhenCallingIsModuleTypeWithMODULE_TYPE_VALIDATOR() external view {
        // it should return true
        bool result = ecdsaValidator.isModuleType(MODULE_TYPE_VALIDATOR);
        assertTrue(result, "Should return true for MODULE_TYPE_VALIDATOR");
    }

    function test_WhenCallingIsModuleTypeWithMODULE_TYPE_HOOK() external view {
        // it should return true
        bool result = ecdsaValidator.isModuleType(MODULE_TYPE_HOOK);
        assertTrue(result, "Should return true for MODULE_TYPE_HOOK");
    }

    function test_WhenCallingIsModuleTypeWithMODULE_TYPE_STATELESS_VALIDATOR() external view {
        // it should return true
        bool result = ecdsaValidator.isModuleType(MODULE_TYPE_STATELESS_VALIDATOR);
        assertTrue(result, "Should return true for MODULE_TYPE_STATELESS_VALIDATOR");
    }

    function test_WhenCallingIsModuleTypeWithMODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER() external view {
        // it should return true
        bool result = ecdsaValidator.isModuleType(MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER);
        assertTrue(result, "Should return true for MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER");
    }

    function test_WhenCallingIsModuleTypeWithAnUnsupportedType() external view {
        // it should return false
        bool result = ecdsaValidator.isModuleType(999);
        assertFalse(result, "Should return false for unsupported type");
    }

    // ==================== onInstall Tests ====================

    function test_WhenCallingOnInstallWithAlreadyInitializedValidator() external {
        // it should revert with AlreadyInitialized
        _installValidator();

        vm.startPrank(wallet);
        vm.expectRevert(abi.encodeWithSelector(IModule.AlreadyInitialized.selector, wallet));
        ecdsaValidator.onInstall(abi.encodePacked(owner));
        vm.stopPrank();
    }

    function test_WhenCallingOnInstallWithInvalidDataLength() external {
        // it should revert with InvalidDataLength
        vm.startPrank(wallet);
        // Data should be 20 bytes (address), send 19 bytes
        bytes memory invalidData = bytes.concat(bytes19(0));
        vm.expectRevert(ECDSAValidator.InvalidDataLength.selector);
        ecdsaValidator.onInstall(invalidData);
        vm.stopPrank();
    }

    function test_WhenCallingOnInstallWithZeroAddressOwner() external {
        // it should revert with ZeroAddressOwner
        vm.startPrank(wallet);
        bytes memory dataWithZeroAddress = abi.encodePacked(address(0));
        vm.expectRevert(ECDSAValidator.ZeroAddressOwner.selector);
        ecdsaValidator.onInstall(dataWithZeroAddress);
        vm.stopPrank();
    }

    function test_WhenCallingOnInstallWithValidData() external {
        // it should store the owner address
        // it should emit OwnerRegistered event
        vm.startPrank(wallet);

        vm.expectEmit(true, true, false, false);
        emit OwnerRegistered(wallet, owner);

        ecdsaValidator.onInstall(abi.encodePacked(owner));
        vm.stopPrank();

        (address storedOwner) = ecdsaValidator.ecdsaValidatorStorage(wallet);
        assertEq(storedOwner, owner, "Owner should be stored correctly");
    }

    // ==================== onUninstall Tests ====================

    function test_WhenCallingOnUninstallWithNotInitializedValidator() external {
        // it should revert with NotInitialized
        vm.startPrank(wallet);
        vm.expectRevert(abi.encodeWithSelector(IModule.NotInitialized.selector, wallet));
        ecdsaValidator.onUninstall("");
        vm.stopPrank();
    }

    function test_WhenCallingOnUninstallWithInitializedValidator() external {
        // it should delete the owner from storage
        _installValidator();

        vm.startPrank(wallet);
        ecdsaValidator.onUninstall("");
        vm.stopPrank();

        (address storedOwner) = ecdsaValidator.ecdsaValidatorStorage(wallet);
        assertEq(storedOwner, address(0), "Owner should be deleted");
    }

    // ==================== validateUserOp Tests ====================

    function test_WhenCallingValidateUserOpWithOwnerNotSet() external {
        // it should return SIG_VALIDATION_FAILED_UINT
        // Note: When owner is not set (address(0)), the signature check will fail
        // because ECDSA.tryRecoverCalldata will not return address(0) for any valid signature
        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);
        userOp.signature = _signRawHash(userOpHash, ownerKey);

        vm.prank(wallet);
        uint256 result = ecdsaValidator.validateUserOp(userOp, userOpHash);
        // When owner is address(0), the signature cannot match it
        assertEq(result, SIG_VALIDATION_FAILED_UINT, "Should return SIG_VALIDATION_FAILED_UINT when owner not set");
    }

    function test_WhenCallingValidateUserOpWithValidRawHashSignature() external {
        // it should return SIG_VALIDATION_SUCCESS_UINT
        _installValidator();

        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);
        userOp.signature = _signRawHash(userOpHash, ownerKey);

        vm.prank(wallet);
        uint256 result = ecdsaValidator.validateUserOp(userOp, userOpHash);
        assertEq(
            result,
            SIG_VALIDATION_SUCCESS_UINT,
            "Should return SIG_VALIDATION_SUCCESS_UINT for valid raw hash signature"
        );
    }

    function test_WhenCallingValidateUserOpWithValidEthSignedMessageHash() external {
        // it should return SIG_VALIDATION_SUCCESS_UINT
        _installValidator();

        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);
        userOp.signature = _signEthSignedMessageHash(userOpHash, ownerKey);

        vm.prank(wallet);
        uint256 result = ecdsaValidator.validateUserOp(userOp, userOpHash);
        assertEq(
            result,
            SIG_VALIDATION_SUCCESS_UINT,
            "Should return SIG_VALIDATION_SUCCESS_UINT for valid eth signed message hash"
        );
    }

    function test_WhenCallingValidateUserOpWithInvalidSignature() external {
        // it should return SIG_VALIDATION_FAILED_UINT
        _installValidator();

        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);
        // Sign with a different hash to create invalid signature
        bytes32 wrongHash = keccak256(abi.encodePacked("wrong"));
        userOp.signature = _signRawHash(wrongHash, ownerKey);

        vm.prank(wallet);
        uint256 result = ecdsaValidator.validateUserOp(userOp, userOpHash);
        assertEq(result, SIG_VALIDATION_FAILED_UINT, "Should return SIG_VALIDATION_FAILED_UINT for invalid signature");
    }

    // ==================== isValidSignatureWithSender Tests ====================

    function test_WhenCallingIsValidSignatureWithSenderWithOwnerNotSet() external {
        // it should return ERC1271_INVALID
        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));
        bytes memory sig = _signRawHash(testHash, ownerKey);

        vm.prank(wallet);
        bytes4 result = ecdsaValidator.isValidSignatureWithSender(address(0), testHash, sig);
        // When owner is address(0), no signature will match
        assertEq(result, ERC1271_INVALID, "Should return ERC1271_INVALID when owner not set");
    }

    function test_WhenCallingIsValidSignatureWithSenderWithValidRawHashSignature() external {
        // it should return ERC1271_MAGICVALUE
        _installValidator();

        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));
        bytes memory sig = _signRawHash(testHash, ownerKey);

        vm.prank(wallet);
        bytes4 result = ecdsaValidator.isValidSignatureWithSender(address(0), testHash, sig);
        assertEq(result, ERC1271_MAGICVALUE, "Should return ERC1271_MAGICVALUE for valid raw hash signature");
    }

    function test_WhenCallingIsValidSignatureWithSenderWithValidEthSignedMessageHash() external {
        // it should return ERC1271_MAGICVALUE
        _installValidator();

        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));
        bytes memory sig = _signEthSignedMessageHash(testHash, ownerKey);

        vm.prank(wallet);
        bytes4 result = ecdsaValidator.isValidSignatureWithSender(address(0), testHash, sig);
        assertEq(result, ERC1271_MAGICVALUE, "Should return ERC1271_MAGICVALUE for valid eth signed message hash");
    }

    function test_WhenCallingIsValidSignatureWithSenderWithInvalidSignature() external {
        // it should return ERC1271_INVALID
        _installValidator();

        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));
        bytes32 wrongHash = keccak256(abi.encodePacked("WRONG_HASH"));
        bytes memory sig = _signRawHash(wrongHash, ownerKey);

        vm.prank(wallet);
        bytes4 result = ecdsaValidator.isValidSignatureWithSender(address(0), testHash, sig);
        assertEq(result, ERC1271_INVALID, "Should return ERC1271_INVALID for invalid signature");
    }

    // ==================== validateSignatureWithData Tests ====================

    function test_WhenCallingValidateSignatureWithDataWithValidRawHashSignature() external view {
        // it should return true
        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));
        bytes memory sig = _signRawHash(testHash, ownerKey);
        bytes memory data = abi.encodePacked(owner);

        bool result = ecdsaValidator.validateSignatureWithData(testHash, sig, data);
        assertTrue(result, "Should return true for valid raw hash signature");
    }

    function test_WhenCallingValidateSignatureWithDataWithValidEthSignedMessageHash() external view {
        // it should return true
        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));
        bytes memory sig = _signEthSignedMessageHash(testHash, ownerKey);
        bytes memory data = abi.encodePacked(owner);

        bool result = ecdsaValidator.validateSignatureWithData(testHash, sig, data);
        assertTrue(result, "Should return true for valid eth signed message hash");
    }

    function test_WhenCallingValidateSignatureWithDataWithInvalidSignature() external view {
        // it should return false
        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));
        bytes32 wrongHash = keccak256(abi.encodePacked("WRONG_HASH"));
        bytes memory sig = _signRawHash(wrongHash, ownerKey);
        bytes memory data = abi.encodePacked(owner);

        bool result = ecdsaValidator.validateSignatureWithData(testHash, sig, data);
        assertFalse(result, "Should return false for invalid signature");
    }

    // ==================== validateSignatureWithDataWithSender Tests ====================

    function test_WhenCallingValidateSignatureWithDataWithSenderWithValidRawHashSignature() external view {
        // it should return true
        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));
        bytes memory sig = _signRawHash(testHash, ownerKey);
        bytes memory data = abi.encodePacked(owner);
        address sender = address(0x5678);

        bool result = ecdsaValidator.validateSignatureWithDataWithSender(sender, testHash, sig, data);
        assertTrue(result, "Should return true for valid raw hash signature");
    }

    function test_WhenCallingValidateSignatureWithDataWithSenderWithValidEthSignedMessageHash() external view {
        // it should return true
        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));
        bytes memory sig = _signEthSignedMessageHash(testHash, ownerKey);
        bytes memory data = abi.encodePacked(owner);
        address sender = address(0x5678);

        bool result = ecdsaValidator.validateSignatureWithDataWithSender(sender, testHash, sig, data);
        assertTrue(result, "Should return true for valid eth signed message hash");
    }

    function test_WhenCallingValidateSignatureWithDataWithSenderWithInvalidSignature() external view {
        // it should return false
        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));
        bytes32 wrongHash = keccak256(abi.encodePacked("WRONG_HASH"));
        bytes memory sig = _signRawHash(wrongHash, ownerKey);
        bytes memory data = abi.encodePacked(owner);
        address sender = address(0x5678);

        bool result = ecdsaValidator.validateSignatureWithDataWithSender(sender, testHash, sig, data);
        assertFalse(result, "Should return false for invalid signature");
    }

    // ==================== preCheck Tests ====================

    function test_WhenCallingPreCheckWithMsgSenderNotTheOwner() external {
        // it should revert with sender is not owner
        _installValidator();

        address notOwner = address(0x9999);

        vm.startPrank(wallet);
        vm.expectRevert(ECDSAValidator.SenderNotOwner.selector);
        ecdsaValidator.preCheck(notOwner, 0, "");
        vm.stopPrank();
    }

    function test_WhenCallingPreCheckWithMsgSenderAsTheOwner() external {
        // it should return empty bytes
        _installValidator();

        vm.prank(wallet);
        bytes memory result = ecdsaValidator.preCheck(owner, 0, "");
        assertEq(result, hex"", "Should return empty bytes");
    }

    // ==================== postCheck Tests ====================

    function test_WhenCallingPostCheckWithAnyHookData() external {
        // it should complete without reverting
        // postCheck is a no-op function that should never revert
        ecdsaValidator.postCheck(hex"1234");
        ecdsaValidator.postCheck("");
        ecdsaValidator.postCheck(abi.encodePacked("some data"));
        // If we reach here without reverting, the test passes
        assertTrue(true, "postCheck should complete without reverting");
    }

    function test_WhenCallingValidateUserOpWithSignatureMatchingViaFirstBranch() external {
        // it should return SIG_VALIDATION_SUCCESS_UINT via raw hash match
        // This tests the first branch: if (signer == ECDSA.tryRecoverCalldata(hash, sig)) return true;
        _installValidator();

        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);
        // Sign the raw hash directly - this should match in the first branch
        userOp.signature = _signRawHash(userOpHash, ownerKey);

        vm.prank(wallet);
        uint256 result = ecdsaValidator.validateUserOp(userOp, userOpHash);
        assertEq(
            result,
            SIG_VALIDATION_SUCCESS_UINT,
            "Should return SIG_VALIDATION_SUCCESS_UINT via raw hash match (first branch)"
        );
    }

    function test_WhenCallingValidateUserOpWithSignatureMatchingViaSecondBranch() external {
        // it should return SIG_VALIDATION_SUCCESS_UINT via eth hash match
        // This tests the second branch: first branch fails, then checks eth signed message hash
        _installValidator();

        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);
        // Sign the eth signed message hash - first branch will fail, second branch will succeed
        userOp.signature = _signEthSignedMessageHash(userOpHash, ownerKey);

        vm.prank(wallet);
        uint256 result = ecdsaValidator.validateUserOp(userOp, userOpHash);
        assertEq(
            result,
            SIG_VALIDATION_SUCCESS_UINT,
            "Should return SIG_VALIDATION_SUCCESS_UINT via eth hash match (second branch)"
        );
    }

    function test_WhenCallingValidateUserOpWithSignatureFailingBothBranches() external {
        // it should return SIG_VALIDATION_FAILED_UINT after checking both hashes
        // This tests when both branches fail: raw hash doesn't match AND eth signed hash doesn't match
        _installValidator();

        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);

        // Create a different keypair to sign - the recovered address won't match owner
        (, uint256 differentKey) = makeAddrAndKey("different");
        userOp.signature = _signRawHash(userOpHash, differentKey);

        vm.prank(wallet);
        uint256 result = ecdsaValidator.validateUserOp(userOp, userOpHash);
        assertEq(
            result, SIG_VALIDATION_FAILED_UINT, "Should return SIG_VALIDATION_FAILED_UINT after both branches fail"
        );
    }

    function test_WhenCallingIsValidSignatureWithSenderWithSignatureMatchingViaFirstBranch() external {
        // it should return ERC1271_MAGICVALUE via raw hash match
        // This tests the first branch: if (signer == ECDSA.tryRecoverCalldata(hash, sig)) return true;
        _installValidator();

        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));
        // Sign the raw hash directly - this should match in the first branch
        bytes memory sig = _signRawHash(testHash, ownerKey);

        vm.prank(wallet);
        bytes4 result = ecdsaValidator.isValidSignatureWithSender(address(0), testHash, sig);
        assertEq(result, ERC1271_MAGICVALUE, "Should return ERC1271_MAGICVALUE via raw hash match (first branch)");
    }

    function test_WhenCallingIsValidSignatureWithSenderWithSignatureMatchingViaSecondBranch() external {
        // it should return ERC1271_MAGICVALUE via eth hash match
        // This tests the second branch: first branch fails, then checks eth signed message hash
        _installValidator();

        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));
        // Sign the eth signed message hash - first branch will fail, second branch will succeed
        bytes memory sig = _signEthSignedMessageHash(testHash, ownerKey);

        vm.prank(wallet);
        bytes4 result = ecdsaValidator.isValidSignatureWithSender(address(0), testHash, sig);
        assertEq(result, ERC1271_MAGICVALUE, "Should return ERC1271_MAGICVALUE via eth hash match (second branch)");
    }

    function test_WhenCallingIsValidSignatureWithSenderWithSignatureFailingBothBranches() external {
        // it should return ERC1271_INVALID after checking both hashes
        // This tests when both branches fail: raw hash doesn't match AND eth signed hash doesn't match
        _installValidator();

        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));

        // Create a different keypair to sign - the recovered address won't match owner
        (, uint256 differentKey) = makeAddrAndKey("different");
        bytes memory sig = _signRawHash(testHash, differentKey);

        vm.prank(wallet);
        bytes4 result = ecdsaValidator.isValidSignatureWithSender(address(0), testHash, sig);
        assertEq(result, ERC1271_INVALID, "Should return ERC1271_INVALID after both branches fail");
    }
}
