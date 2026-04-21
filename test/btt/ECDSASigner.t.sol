// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {ECDSASigner} from "src/signers/ECDSASigner.sol";
import {ISigner} from "src/interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {
    SIG_VALIDATION_SUCCESS_UINT,
    SIG_VALIDATION_FAILED_UINT,
    MODULE_TYPE_SIGNER,
    MODULE_TYPE_STATELESS_VALIDATOR,
    MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER,
    ERC1271_MAGICVALUE,
    ERC1271_INVALID
} from "src/types/Constants.sol";

contract ECDSASignerBTTTest is Test {
    ECDSASigner public ecdsaSigner;
    IEntryPoint public ENTRYPOINT;

    address public owner;
    uint256 public ownerKey;
    address public wallet;
    bytes32 public signerId;

    function setUp() public {
        ecdsaSigner = new ECDSASigner();
        ENTRYPOINT = EntryPointLib.deploy();
        (owner, ownerKey) = makeAddrAndKey("owner");
        wallet = address(0x1234);
        signerId = keccak256(abi.encodePacked("SIGNER_ID_1"));
    }

    // ==================== Helper Functions ====================

    function _installSigner() internal {
        vm.prank(wallet);
        ecdsaSigner.onInstall(abi.encodePacked(signerId, owner));
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

    function test_WhenCallingIsModuleTypeWithMODULE_TYPE_SIGNER() external view {
        // it should return true
        bool result = ecdsaSigner.isModuleType(MODULE_TYPE_SIGNER);
        assertTrue(result, "Should return true for MODULE_TYPE_SIGNER");
    }

    function test_WhenCallingIsModuleTypeWithMODULE_TYPE_STATELESS_VALIDATOR() external view {
        // it should return true
        bool result = ecdsaSigner.isModuleType(MODULE_TYPE_STATELESS_VALIDATOR);
        assertTrue(result, "Should return true for MODULE_TYPE_STATELESS_VALIDATOR");
    }

    function test_WhenCallingIsModuleTypeWithMODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER() external view {
        // it should return true
        bool result = ecdsaSigner.isModuleType(MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER);
        assertTrue(result, "Should return true for MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER");
    }

    function test_WhenCallingIsModuleTypeWithAnUnsupportedType() external view {
        // it should return false
        bool result = ecdsaSigner.isModuleType(999);
        assertFalse(result, "Should return false for unsupported type");
    }

    // ==================== onInstall Tests ====================

    function test_WhenCallingOnInstallWithInvalidDataLength() external {
        // it should revert with InvalidDataLength
        vm.startPrank(wallet);
        // Data should be 32 bytes (signerId) + 20 bytes (address) = 52 bytes
        // Send only 32 bytes (signerId) + 19 bytes = 51 bytes (invalid)
        bytes memory invalidData = abi.encodePacked(signerId, bytes19(0));
        vm.expectRevert(ECDSASigner.InvalidDataLength.selector);
        ecdsaSigner.onInstall(invalidData);
        vm.stopPrank();
    }

    function test_WhenCallingOnInstallWithZeroAddressSigner() external {
        // it should revert with ZeroAddressSigner
        vm.startPrank(wallet);
        bytes memory dataWithZeroAddress = abi.encodePacked(signerId, address(0));
        vm.expectRevert(ECDSASigner.ZeroAddressSigner.selector);
        ecdsaSigner.onInstall(dataWithZeroAddress);
        vm.stopPrank();
    }

    function test_WhenCallingOnInstallWithAlreadyInstalledSignerForSameId() external {
        // it should revert with Already installed
        _installSigner();

        vm.startPrank(wallet);
        vm.expectRevert("Already installed");
        ecdsaSigner.onInstall(abi.encodePacked(signerId, owner));
        vm.stopPrank();
    }

    function test_WhenCallingOnInstallWithValidData() external {
        // it should store the signer address
        _installSigner();

        address storedSigner = ecdsaSigner.signer(signerId, wallet);
        assertEq(storedSigner, owner, "Signer should be stored correctly");
    }

    // ==================== onUninstall Tests ====================

    function test_RevertWhen_CallingOnUninstallWithSignerNotInstalled() external {
        // it should revert
        vm.startPrank(wallet);
        vm.expectRevert();
        ecdsaSigner.onUninstall(abi.encodePacked(signerId, ""));
        vm.stopPrank();
    }

    function test_WhenCallingOnUninstallWithSignerInstalled() external {
        // it should delete the signer mapping
        _installSigner();

        vm.startPrank(wallet);
        ecdsaSigner.onUninstall(abi.encodePacked(signerId, ""));
        vm.stopPrank();

        address storedSigner = ecdsaSigner.signer(signerId, wallet);
        assertEq(storedSigner, address(0), "Signer should be deleted");
    }

    // ==================== checkUserOpSignature Tests ====================

    function test_WhenCallingCheckUserOpSignatureWithSignerNotInstalled() external {
        // it should return SIG_VALIDATION_FAILED_UINT
        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);
        userOp.signature = _signRawHash(userOpHash, ownerKey);

        vm.prank(wallet);
        uint256 result = ecdsaSigner.checkUserOpSignature(signerId, userOp, userOpHash);
        assertEq(
            result, SIG_VALIDATION_FAILED_UINT, "Should return SIG_VALIDATION_FAILED_UINT when signer not installed"
        );
    }

    function test_WhenCallingCheckUserOpSignatureWithValidRawHashSignature() external {
        // it should return SIG_VALIDATION_SUCCESS_UINT
        _installSigner();

        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);
        userOp.signature = _signRawHash(userOpHash, ownerKey);

        vm.prank(wallet);
        uint256 result = ecdsaSigner.checkUserOpSignature(signerId, userOp, userOpHash);
        assertEq(
            result,
            SIG_VALIDATION_SUCCESS_UINT,
            "Should return SIG_VALIDATION_SUCCESS_UINT for valid raw hash signature"
        );
    }

    function test_WhenCallingCheckUserOpSignatureWithValidEthSignedMessageHash() external {
        // it should return SIG_VALIDATION_SUCCESS_UINT
        _installSigner();

        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);
        userOp.signature = _signEthSignedMessageHash(userOpHash, ownerKey);

        vm.prank(wallet);
        uint256 result = ecdsaSigner.checkUserOpSignature(signerId, userOp, userOpHash);
        assertEq(
            result,
            SIG_VALIDATION_SUCCESS_UINT,
            "Should return SIG_VALIDATION_SUCCESS_UINT for valid eth signed message hash"
        );
    }

    function test_WhenCallingCheckUserOpSignatureWithInvalidSignature() external {
        // it should return SIG_VALIDATION_FAILED_UINT
        _installSigner();

        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);
        // Sign with a different hash to create invalid signature
        bytes32 wrongHash = keccak256(abi.encodePacked("wrong"));
        userOp.signature = _signRawHash(wrongHash, ownerKey);

        vm.prank(wallet);
        uint256 result = ecdsaSigner.checkUserOpSignature(signerId, userOp, userOpHash);
        assertEq(result, SIG_VALIDATION_FAILED_UINT, "Should return SIG_VALIDATION_FAILED_UINT for invalid signature");
    }

    // ==================== checkSignature Tests ====================

    function test_WhenCallingCheckSignatureWithSignerNotInstalled() external {
        // it should return ERC1271_INVALID
        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));
        bytes memory sig = _signRawHash(testHash, ownerKey);

        vm.prank(wallet);
        bytes4 result = ecdsaSigner.checkSignature(signerId, address(0), testHash, sig);
        assertEq(result, ERC1271_INVALID, "Should return ERC1271_INVALID when signer not installed");
    }

    function test_WhenCallingCheckSignatureWithValidRawHashSignature() external {
        // it should return ERC1271_MAGICVALUE
        _installSigner();

        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));
        bytes memory sig = _signRawHash(testHash, ownerKey);

        vm.prank(wallet);
        bytes4 result = ecdsaSigner.checkSignature(signerId, address(0), testHash, sig);
        assertEq(result, ERC1271_MAGICVALUE, "Should return ERC1271_MAGICVALUE for valid raw hash signature");
    }

    function test_WhenCallingCheckSignatureWithValidEthSignedMessageHash() external {
        // it should return ERC1271_MAGICVALUE
        _installSigner();

        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));
        bytes memory sig = _signEthSignedMessageHash(testHash, ownerKey);

        vm.prank(wallet);
        bytes4 result = ecdsaSigner.checkSignature(signerId, address(0), testHash, sig);
        assertEq(result, ERC1271_MAGICVALUE, "Should return ERC1271_MAGICVALUE for valid eth signed message hash");
    }

    function test_WhenCallingCheckSignatureWithInvalidSignature() external {
        // it should return ERC1271_INVALID
        _installSigner();

        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));
        bytes32 wrongHash = keccak256(abi.encodePacked("WRONG_HASH"));
        bytes memory sig = _signRawHash(wrongHash, ownerKey);

        vm.prank(wallet);
        bytes4 result = ecdsaSigner.checkSignature(signerId, address(0), testHash, sig);
        assertEq(result, ERC1271_INVALID, "Should return ERC1271_INVALID for invalid signature");
    }

    // ==================== validateSignatureWithData Tests ====================

    function test_WhenCallingValidateSignatureWithDataWithValidRawHashSignature() external view {
        // it should return true
        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));
        bytes memory sig = _signRawHash(testHash, ownerKey);
        bytes memory data = abi.encodePacked(owner);

        bool result = ecdsaSigner.validateSignatureWithData(testHash, sig, data);
        assertTrue(result, "Should return true for valid raw hash signature");
    }

    function test_WhenCallingValidateSignatureWithDataWithValidEthSignedMessageHash() external view {
        // it should return true
        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));
        bytes memory sig = _signEthSignedMessageHash(testHash, ownerKey);
        bytes memory data = abi.encodePacked(owner);

        bool result = ecdsaSigner.validateSignatureWithData(testHash, sig, data);
        assertTrue(result, "Should return true for valid eth signed message hash");
    }

    function test_WhenCallingValidateSignatureWithDataWithInvalidSignature() external view {
        // it should return false
        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));
        bytes32 wrongHash = keccak256(abi.encodePacked("WRONG_HASH"));
        bytes memory sig = _signRawHash(wrongHash, ownerKey);
        bytes memory data = abi.encodePacked(owner);

        bool result = ecdsaSigner.validateSignatureWithData(testHash, sig, data);
        assertFalse(result, "Should return false for invalid signature");
    }

    // ==================== validateSignatureWithDataWithSender Tests ====================

    function test_WhenCallingValidateSignatureWithDataWithSenderWithValidRawHashSignature() external view {
        // it should return true
        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));
        bytes memory sig = _signRawHash(testHash, ownerKey);
        bytes memory data = abi.encodePacked(owner);
        address sender = address(0x5678);

        bool result = ecdsaSigner.validateSignatureWithDataWithSender(sender, testHash, sig, data);
        assertTrue(result, "Should return true for valid raw hash signature");
    }

    function test_WhenCallingValidateSignatureWithDataWithSenderWithValidEthSignedMessageHash() external view {
        // it should return true
        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));
        bytes memory sig = _signEthSignedMessageHash(testHash, ownerKey);
        bytes memory data = abi.encodePacked(owner);
        address sender = address(0x5678);

        bool result = ecdsaSigner.validateSignatureWithDataWithSender(sender, testHash, sig, data);
        assertTrue(result, "Should return true for valid eth signed message hash");
    }

    function test_WhenCallingValidateSignatureWithDataWithSenderWithInvalidSignature() external view {
        // it should return false
        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));
        bytes32 wrongHash = keccak256(abi.encodePacked("WRONG_HASH"));
        bytes memory sig = _signRawHash(wrongHash, ownerKey);
        bytes memory data = abi.encodePacked(owner);
        address sender = address(0x5678);

        bool result = ecdsaSigner.validateSignatureWithDataWithSender(sender, testHash, sig, data);
        assertFalse(result, "Should return false for invalid signature");
    }

    function test_WhenCallingCheckUserOpSignatureWithSignerInstalledAndSignatureReturnsSuccessViaFirstBranch()
        external
    {
        // it should return SIG_VALIDATION_SUCCESS_UINT via raw hash match
        // This tests the first branch: if (_signer == ECDSA.tryRecoverCalldata(hash, sig)) return true;
        _installSigner();

        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);
        // Sign the raw hash directly - this should match in the first branch
        userOp.signature = _signRawHash(userOpHash, ownerKey);

        vm.prank(wallet);
        uint256 result = ecdsaSigner.checkUserOpSignature(signerId, userOp, userOpHash);
        assertEq(
            result,
            SIG_VALIDATION_SUCCESS_UINT,
            "Should return SIG_VALIDATION_SUCCESS_UINT via raw hash match (first branch)"
        );
    }

    function test_WhenCallingCheckUserOpSignatureWithSignerInstalledAndSignatureReturnsSuccessViaSecondBranch()
        external
    {
        // it should return SIG_VALIDATION_SUCCESS_UINT via eth hash match
        // This tests the second branch: first branch fails, then checks eth signed message hash
        _installSigner();

        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);
        // Sign the eth signed message hash - first branch will fail, second branch will succeed
        userOp.signature = _signEthSignedMessageHash(userOpHash, ownerKey);

        vm.prank(wallet);
        uint256 result = ecdsaSigner.checkUserOpSignature(signerId, userOp, userOpHash);
        assertEq(
            result,
            SIG_VALIDATION_SUCCESS_UINT,
            "Should return SIG_VALIDATION_SUCCESS_UINT via eth hash match (second branch)"
        );
    }

    function test_WhenCallingCheckUserOpSignatureWithSignerInstalledAndSignatureFailsBothBranches() external {
        // it should return SIG_VALIDATION_FAILED_UINT after checking both hashes
        // This tests when both branches fail: raw hash doesn't match AND eth signed hash doesn't match
        _installSigner();

        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);

        // Create a different keypair to sign - the recovered address won't match owner
        (, uint256 differentKey) = makeAddrAndKey("different");
        userOp.signature = _signRawHash(userOpHash, differentKey);

        vm.prank(wallet);
        uint256 result = ecdsaSigner.checkUserOpSignature(signerId, userOp, userOpHash);
        assertEq(
            result,
            SIG_VALIDATION_FAILED_UINT,
            "Should return SIG_VALIDATION_FAILED_UINT after both branches fail"
        );
    }

    function test_WhenCallingCheckSignatureWithSignerInstalledAndSignatureReturnsSuccessViaFirstBranch() external {
        // it should return ERC1271_MAGICVALUE via raw hash match
        // This tests the first branch: if (_signer == ECDSA.tryRecoverCalldata(hash, sig)) return true;
        _installSigner();

        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));
        // Sign the raw hash directly - this should match in the first branch
        bytes memory sig = _signRawHash(testHash, ownerKey);

        vm.prank(wallet);
        bytes4 result = ecdsaSigner.checkSignature(signerId, address(0), testHash, sig);
        assertEq(result, ERC1271_MAGICVALUE, "Should return ERC1271_MAGICVALUE via raw hash match (first branch)");
    }

    function test_WhenCallingCheckSignatureWithSignerInstalledAndSignatureReturnsSuccessViaSecondBranch() external {
        // it should return ERC1271_MAGICVALUE via eth hash match
        // This tests the second branch: first branch fails, then checks eth signed message hash
        _installSigner();

        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));
        // Sign the eth signed message hash - first branch will fail, second branch will succeed
        bytes memory sig = _signEthSignedMessageHash(testHash, ownerKey);

        vm.prank(wallet);
        bytes4 result = ecdsaSigner.checkSignature(signerId, address(0), testHash, sig);
        assertEq(result, ERC1271_MAGICVALUE, "Should return ERC1271_MAGICVALUE via eth hash match (second branch)");
    }

    function test_WhenCallingCheckSignatureWithSignerInstalledAndSignatureFailsBothBranches() external {
        // it should return ERC1271_INVALID after checking both hashes
        // This tests when both branches fail: raw hash doesn't match AND eth signed hash doesn't match
        _installSigner();

        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));

        // Create a different keypair to sign - the recovered address won't match owner
        (, uint256 differentKey) = makeAddrAndKey("different");
        bytes memory sig = _signRawHash(testHash, differentKey);

        vm.prank(wallet);
        bytes4 result = ecdsaSigner.checkSignature(signerId, address(0), testHash, sig);
        assertEq(result, ERC1271_INVALID, "Should return ERC1271_INVALID after both branches fail");
    }
}
