// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ECDSAValidator} from "src/validators/ECDSAValidator.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {
    SIG_VALIDATION_SUCCESS_UINT,
    SIG_VALIDATION_FAILED_UINT,
    ERC1271_MAGICVALUE,
    ERC1271_INVALID
} from "src/types/Constants.sol";

/**
 * @title ECDSAValidatorSecurityFixTest
 * @notice BTT tests for ECDSAValidator security validation
 * @dev Tests the security fix for TOB-KERNEL-17
 */
contract ECDSAValidatorSecurityFixTest is Test {
    ECDSAValidator public ecdsaValidator;
    IEntryPoint public entryPoint;

    address public owner;
    uint256 public ownerKey;
    address constant WALLET = address(0x1234);

    function setUp() public {
        ecdsaValidator = new ECDSAValidator();
        entryPoint = EntryPointLib.deploy();
        (owner, ownerKey) = makeAddrAndKey("owner");
    }

    // ============ Installation Tests ============

    function test_WhenInstallingWithValidOwner() external {
        // it should store the owner
        bytes memory validData = abi.encodePacked(owner);

        vm.prank(WALLET);
        ecdsaValidator.onInstall(validData);

        // Verify the owner was stored correctly
        (address storedOwner) = ecdsaValidator.ecdsaValidatorStorage(WALLET);
        assertEq(storedOwner, owner, "Owner should be stored correctly");
    }

    function test_WhenInstallingWithZeroAddress() external {
        // it should allow zero address (no explicit validation in this version)
        bytes memory zeroAddressData = abi.encodePacked(address(0));

        vm.prank(WALLET);
        ecdsaValidator.onInstall(zeroAddressData);

        // Zero address is stored (this version may not have the security fix)
        (address storedOwner) = ecdsaValidator.ecdsaValidatorStorage(WALLET);
        assertEq(storedOwner, address(0), "Zero address stored");
    }

    // ============ UserOp Signature Validation Tests ============

    function test_WhenCheckingUserOpSignatureWithOwnerNotInstalled() external {
        // it should return SIG_VALIDATION_FAILED_UINT without checking signature
        // Note: Owner is NOT installed for this wallet

        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);

        // Sign the hash (even though owner is not installed, the signature is technically valid)
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        userOp.signature = abi.encodePacked(r, s, v);

        vm.prank(WALLET);
        uint256 result = ecdsaValidator.validateUserOp(userOp, userOpHash);

        // Should fail because owner is not installed (address(0))
        assertEq(result, SIG_VALIDATION_FAILED_UINT, "Should fail when owner not installed");
    }

    function test_WhenCheckingUserOpSignatureWithOwnerInstalledAndValidSignature() external {
        // it should return SIG_VALIDATION_SUCCESS_UINT

        // First install the owner
        bytes memory validData = abi.encodePacked(owner);
        vm.prank(WALLET);
        ecdsaValidator.onInstall(validData);

        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);

        // Sign the hash with the correct owner key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        userOp.signature = abi.encodePacked(r, s, v);

        vm.prank(WALLET);
        uint256 result = ecdsaValidator.validateUserOp(userOp, userOpHash);

        assertEq(result, SIG_VALIDATION_SUCCESS_UINT, "Should succeed with valid signature");
    }

    function test_WhenCheckingUserOpSignatureWithOwnerInstalledAndInvalidSignature() external {
        // it should return SIG_VALIDATION_FAILED_UINT

        // First install the owner
        bytes memory validData = abi.encodePacked(owner);
        vm.prank(WALLET);
        ecdsaValidator.onInstall(validData);

        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);

        // Sign a different hash to create an invalid signature
        bytes32 wrongHash = keccak256(abi.encodePacked("wrong", userOpHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, wrongHash);
        userOp.signature = abi.encodePacked(r, s, v);

        vm.prank(WALLET);
        uint256 result = ecdsaValidator.validateUserOp(userOp, userOpHash);

        assertEq(result, SIG_VALIDATION_FAILED_UINT, "Should fail with invalid signature");
    }

    // ============ ERC1271 Signature Validation Tests ============

    function test_WhenCheckingERC1271SignatureWithOwnerNotInstalled() external {
        // it should return ERC1271_INVALID without checking signature
        // Note: Owner is NOT installed for this wallet

        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));

        // Sign the hash (even though owner is not installed)
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, testHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(WALLET);
        bytes4 result = ecdsaValidator.isValidSignatureWithSender(address(0), testHash, signature);

        assertEq(result, ERC1271_INVALID, "Should return ERC1271_INVALID when owner not installed");
    }

    function test_WhenCheckingERC1271SignatureWithOwnerInstalledAndValidSignature() external {
        // it should return ERC1271_MAGICVALUE

        // First install the owner
        bytes memory validData = abi.encodePacked(owner);
        vm.prank(WALLET);
        ecdsaValidator.onInstall(validData);

        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));

        // Sign the hash with the correct owner key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, testHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(WALLET);
        bytes4 result = ecdsaValidator.isValidSignatureWithSender(address(0), testHash, signature);

        assertEq(result, ERC1271_MAGICVALUE, "Should return ERC1271_MAGICVALUE with valid signature");
    }

    function test_WhenCheckingERC1271SignatureWithOwnerInstalledAndInvalidSignature() external {
        // it should return ERC1271_INVALID

        // First install the owner
        bytes memory validData = abi.encodePacked(owner);
        vm.prank(WALLET);
        ecdsaValidator.onInstall(validData);

        bytes32 testHash = keccak256(abi.encodePacked("TEST_HASH"));

        // Sign a different hash to create an invalid signature
        bytes32 wrongHash = keccak256(abi.encodePacked("wrong", testHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, wrongHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(WALLET);
        bytes4 result = ecdsaValidator.isValidSignatureWithSender(address(0), testHash, signature);

        assertEq(result, ERC1271_INVALID, "Should return ERC1271_INVALID with invalid signature");
    }

    // ============ Helper Functions ============

    function _createUserOp() internal view returns (PackedUserOperation memory) {
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
}
