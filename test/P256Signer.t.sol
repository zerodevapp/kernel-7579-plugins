// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {SignerTestBase} from "test/base/SignerTestBase.sol";
import {StatelessValidatorTestBase} from "test/base/StatelessValidatorTestBase.sol";
import {StatelessValidatorWithSenderTestBase} from "test/base/StatelessValidatorWithSenderTestBase.sol";
import {P256Signer} from "src/signers/P256Signer.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IModule, ISigner, IStatelessValidator} from "src/interfaces/IERC7579Modules.sol";
import {SIG_VALIDATION_FAILED_UINT, ERC1271_INVALID} from "src/types/Constants.sol";

contract P256SignerTest is SignerTestBase, StatelessValidatorTestBase, StatelessValidatorWithSenderTestBase {
    uint256 internal constant P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    uint256 internal constant PRIVATE_KEY = 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890;

    uint256 internal pubKeyX;
    uint256 internal pubKeyY;

    function deployModule() internal override returns (IModule) {
        return new P256Signer();
    }

    function _initializeTest() internal override {
        (pubKeyX, pubKeyY) = vm.publicKeyP256(PRIVATE_KEY);
    }

    function installData() internal view override returns (bytes memory) {
        return abi.encode(pubKeyX, pubKeyY);
    }

    function userOpSignature(PackedUserOperation memory userOp, bool valid)
        internal
        view
        override
        returns (bytes memory)
    {
        bytes32 hash = ENTRYPOINT.getUserOpHash(userOp);
        return _signature(valid ? hash : keccak256(abi.encodePacked("invalid", hash)), PRIVATE_KEY);
    }

    function erc1271Signature(bytes32 hash, bool valid) internal pure override returns (address, bytes memory) {
        return (address(0), _signature(valid ? hash : keccak256(abi.encodePacked("invalid", hash)), PRIVATE_KEY));
    }

    function statelessValidationSignature(bytes32 hash, bool valid)
        internal
        pure
        override
        returns (address, bytes memory)
    {
        return erc1271Signature(hash, valid);
    }

    function statelessValidationSignatureWithSender(bytes32 hash, bool valid)
        internal
        pure
        override
        returns (address, bytes memory)
    {
        return erc1271Signature(hash, valid);
    }

    function _afterInstallCheck(bytes32 id) internal view override {
        (uint256 x, uint256 y) = P256Signer(address(module)).p256SignerStorage(id, WALLET);
        assertEq(x, pubKeyX);
        assertEq(y, pubKeyY);
        assertTrue(P256Signer(address(module)).isInitialized(id, WALLET));
    }

    function _afterUninstallCheck(bytes32 id) internal view override {
        (uint256 x, uint256 y) = P256Signer(address(module)).p256SignerStorage(id, WALLET);
        assertEq(x, 0);
        assertEq(y, 0);
        assertFalse(P256Signer(address(module)).isInitialized(id, WALLET));
    }

    function testOnInstallRejectsInvalidLength() public {
        vm.prank(WALLET);
        vm.expectRevert(P256Signer.InvalidDataLength.selector);
        ISigner(address(module)).onInstall(abi.encodePacked(signerId(), hex"01"));
    }

    function testOnInstallRejectsOffCurveKey() public {
        vm.prank(WALLET);
        vm.expectRevert(P256Signer.InvalidPublicKey.selector);
        ISigner(address(module)).onInstall(abi.encodePacked(signerId(), abi.encode(uint256(1), uint256(0))));
    }

    function testUninitializedValidationFailsWithoutReverting() public {
        PackedUserOperation memory userOp;
        userOp.sender = WALLET;
        userOp.signature = _signature(bytes32(uint256(1)), PRIVATE_KEY);

        vm.prank(WALLET);
        assertEq(
            ISigner(address(module)).checkUserOpSignature(signerId(), userOp, bytes32(uint256(1))),
            SIG_VALIDATION_FAILED_UINT
        );

        vm.prank(WALLET);
        assertEq(
            ISigner(address(module)).checkSignature(signerId(), address(0), bytes32(uint256(1)), userOp.signature),
            ERC1271_INVALID
        );
    }

    function testStatelessValidationUsesSuppliedKeyWithoutInstall() public view {
        uint256 otherKey = PRIVATE_KEY + 1;
        (uint256 otherX, uint256 otherY) = vm.publicKeyP256(otherKey);
        bytes32 hash = keccak256("stateless P256 signer");

        assertTrue(
            IStatelessValidator(address(module))
                .validateSignatureWithData(hash, _signature(hash, otherKey), abi.encode(otherX, otherY))
        );
    }

    function testStatelessValidationRejectsMalformedSignature() public view {
        assertFalse(
            IStatelessValidator(address(module)).validateSignatureWithData(bytes32(uint256(1)), hex"01", installData())
        );
    }

    function _signature(bytes32 hash, uint256 privateKey) internal pure returns (bytes memory) {
        (bytes32 r, bytes32 s) = vm.signP256(privateKey, hash);
        uint256 normalizedS = uint256(s);
        if (normalizedS > P256_N / 2) normalizedS = P256_N - normalizedS;
        return abi.encode(r, bytes32(normalizedS));
    }
}
