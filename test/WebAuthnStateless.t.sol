// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {IStatelessValidator, IStatelessValidatorWithSender} from "src/interfaces/IERC7579Modules.sol";
import {MODULE_TYPE_STATELESS_VALIDATOR, MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER} from "src/types/Constants.sol";
import {WebAuthnValidator, WebAuthnValidatorData} from "src/validators/WebAuthnValidator.sol";
import {WebAuthnSigner, WebAuthnSignerData} from "src/signers/WebAuthnSigner.sol";
import {Base64} from "solady/utils/Base64.sol";

contract WebAuthnStatelessTest is Test {
    uint256 internal constant P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    uint256 internal constant PRIVATE_KEY = 0x234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1;

    WebAuthnValidator internal validator;
    WebAuthnSigner internal signer;
    uint256 internal pubKeyX;
    uint256 internal pubKeyY;

    function setUp() public {
        validator = new WebAuthnValidator();
        signer = new WebAuthnSigner();
        (pubKeyX, pubKeyY) = vm.publicKeyP256(PRIVATE_KEY);
    }

    function testModulesAdvertiseStatelessInterfaces() public view {
        assertTrue(validator.isModuleType(MODULE_TYPE_STATELESS_VALIDATOR));
        assertTrue(validator.isModuleType(MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER));
        assertTrue(signer.isModuleType(MODULE_TYPE_STATELESS_VALIDATOR));
        assertTrue(signer.isModuleType(MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER));
    }

    function testValidatorStatelessValidationUsesSuppliedKeyWithoutInstall() public view {
        bytes32 hash = keccak256("stateless WebAuthn validator");
        assertTrue(
            IStatelessValidator(address(validator)).validateSignatureWithData(hash, _signature(hash), _validatorData())
        );
    }

    function testSignerStatelessValidationUsesSuppliedKeyWithoutInstall() public view {
        bytes32 hash = keccak256("stateless WebAuthn signer");
        assertTrue(
            IStatelessValidator(address(signer)).validateSignatureWithData(hash, _signature(hash), _signerData())
        );
    }

    function testStatelessValidationWithSenderUsesSuppliedKey() public view {
        bytes32 hash = keccak256("stateless WebAuthn with sender");
        address requestingProtocol = address(0xBEEF);

        assertTrue(
            IStatelessValidatorWithSender(address(validator))
                .validateSignatureWithDataWithSender(requestingProtocol, hash, _signature(hash), _validatorData())
        );
        assertTrue(
            IStatelessValidatorWithSender(address(signer))
                .validateSignatureWithDataWithSender(requestingProtocol, hash, _signature(hash), _signerData())
        );
    }

    function testStatelessValidationRejectsDifferentChallenge() public view {
        bytes32 signedHash = keccak256("signed WebAuthn challenge");
        bytes32 requestedHash = keccak256("different WebAuthn challenge");

        assertFalse(
            IStatelessValidator(address(validator))
                .validateSignatureWithData(requestedHash, _signature(signedHash), _validatorData())
        );
        assertFalse(
            IStatelessValidator(address(signer))
                .validateSignatureWithData(requestedHash, _signature(signedHash), _signerData())
        );
    }

    function testStatelessValidationRequiresUserPresenceAndVerification() public view {
        bytes32 hash = keccak256("WebAuthn flags");

        assertFalse(
            IStatelessValidator(address(validator))
                .validateSignatureWithData(hash, _signature(hash, 0x04), _validatorData())
        );
        assertFalse(
            IStatelessValidator(address(signer)).validateSignatureWithData(hash, _signature(hash, 0x01), _signerData())
        );
    }

    function testStatelessValidationUsesDynamicClientDataLocations() public view {
        bytes32 hash = keccak256("dynamic WebAuthn locations");
        bytes memory signature = _signature(hash, 0x05, '{"origin":"https://example.com",');

        assertTrue(IStatelessValidator(address(validator)).validateSignatureWithData(hash, signature, _validatorData()));
        assertTrue(IStatelessValidator(address(signer)).validateSignatureWithData(hash, signature, _signerData()));
    }

    function testStatelessValidationRejectsMalformedOrZeroKeyData() public view {
        bytes32 hash = keccak256("bad WebAuthn config");
        bytes memory signature = _signature(hash);

        assertFalse(IStatelessValidator(address(validator)).validateSignatureWithData(hash, signature, hex"01"));
        assertFalse(
            IStatelessValidator(address(signer))
                .validateSignatureWithData(hash, signature, abi.encode(uint256(0), uint256(0), bytes32(0)))
        );
    }

    function _validatorData() internal view returns (bytes memory) {
        return abi.encode(WebAuthnValidatorData(pubKeyX, pubKeyY), bytes32(0));
    }

    function _signerData() internal view returns (bytes memory) {
        return abi.encode(WebAuthnSignerData(pubKeyX, pubKeyY), bytes32(0));
    }

    function _signature(bytes32 hash) internal pure returns (bytes memory) {
        return _signature(hash, 0x05);
    }

    function _signature(bytes32 hash, uint8 flags) internal pure returns (bytes memory) {
        return _signature(hash, flags, "{");
    }

    function _signature(bytes32 hash, uint8 flags, string memory clientDataPrefix)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory authenticatorData = new bytes(37);
        authenticatorData[32] = bytes1(flags);

        string memory challenge = Base64.encode(abi.encodePacked(hash), true, true);
        string memory clientDataJSON =
            string.concat(clientDataPrefix, '"type":"webauthn.get",', '"challenge":"', challenge, '"}');
        uint256 responseTypeLocation = bytes(clientDataPrefix).length;
        uint256 challengeLocation = responseTypeLocation + 22;
        bytes32 messageHash = sha256(abi.encodePacked(authenticatorData, sha256(bytes(clientDataJSON))));
        (bytes32 r, bytes32 s) = vm.signP256(PRIVATE_KEY, messageHash);
        uint256 normalizedS = uint256(s);
        if (normalizedS > P256_N / 2) normalizedS = P256_N - normalizedS;

        return
            abi.encode(
                authenticatorData, clientDataJSON, challengeLocation, responseTypeLocation, uint256(r), normalizedS
            );
    }
}
