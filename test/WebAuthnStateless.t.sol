// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {IStatelessValidator, IStatelessValidatorWithSender} from "src/interfaces/IERC7579Modules.sol";
import {
    MODULE_TYPE_STATELESS_VALIDATOR,
    MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER,
    ERC1271_MAGICVALUE
} from "src/types/Constants.sol";
import {WebAuthnValidator, WebAuthnValidatorData} from "src/validators/WebAuthnValidator.sol";
import {WebAuthnSigner, WebAuthnSignerData} from "src/signers/WebAuthnSigner.sol";
import {P256Validation} from "src/utils/P256Validation.sol";
import {Base64} from "solady/utils/Base64.sol";

contract WebAuthnStatelessTest is Test {
    uint256 internal constant P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    uint256 internal constant PRIVATE_KEY = 0x234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1;
    address internal constant P256_PRECOMPILE = address(0x100);
    address internal constant SOLADY_VERIFIER = 0x000000000000D01eA45F9eFD5c54f037Fa57Ea1a;
    address internal constant SOLADY_CANARY = 0x0000000000001Ab2e8006Fd8B71907bf06a5BDEE;
    address internal constant DAIMO_VERIFIER = 0xc2b78104907F722DABAc4C69f826a522B2754De4;
    uint256 internal constant ZERO_X_VALID_Y = 0x66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4;
    address internal constant ACCOUNT = address(0xA11CE);

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

    function testStatelessValidationUsesLegacyFixedChallengeLocation() public view {
        bytes32 hash = keccak256("legacy WebAuthn locations");
        bytes memory signature = _signature(hash, 0x05, '{"origin":"https://example.com",');

        assertFalse(
            IStatelessValidator(address(validator)).validateSignatureWithData(hash, signature, _validatorData())
        );
        assertFalse(IStatelessValidator(address(signer)).validateSignatureWithData(hash, signature, _signerData()));
    }

    function testLegacySignatureAbiIgnoresUsePrecompiledFlag() public view {
        bytes32 hash = keccak256("legacy WebAuthn verifier flag");
        bytes memory signature = _withUsePrecompiled(_signature(hash), true);

        assertTrue(IStatelessValidator(address(validator)).validateSignatureWithData(hash, signature, _validatorData()));
        assertTrue(IStatelessValidator(address(signer)).validateSignatureWithData(hash, signature, _signerData()));
    }

    function testStatefulModulesAcceptLegacySignatureEncoding() public {
        bytes32 id = keccak256("WebAuthn signer id");
        bytes32 hash = keccak256("stateful legacy WebAuthn signature");
        bytes memory signature = _signature(hash);

        vm.startPrank(ACCOUNT);
        validator.onInstall(_validatorData());
        signer.onInstall(abi.encodePacked(id, _signerData()));

        assertEq(validator.isValidSignatureWithSender(address(0), hash, signature), ERC1271_MAGICVALUE);
        assertEq(signer.checkSignature(id, address(0), hash, signature), ERC1271_MAGICVALUE);
        vm.stopPrank();
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

    function testRejectsOffCurvePublicKeys() public {
        bytes32 hash = keccak256("off-curve WebAuthn key");
        bytes memory signature = _signature(hash);
        bytes memory validatorData = abi.encode(WebAuthnValidatorData(1, 1), bytes32(0));
        bytes memory signerData = abi.encode(WebAuthnSignerData(1, 1), bytes32(0));

        assertFalse(IStatelessValidator(address(validator)).validateSignatureWithData(hash, signature, validatorData));
        assertFalse(IStatelessValidator(address(signer)).validateSignatureWithData(hash, signature, signerData));

        vm.startPrank(ACCOUNT);
        vm.expectRevert(WebAuthnValidator.InvalidPublicKey.selector);
        validator.onInstall(validatorData);

        vm.expectRevert(WebAuthnSigner.InvalidPublicKey.selector);
        signer.onInstall(abi.encodePacked(bytes32(uint256(1)), signerData));
        vm.stopPrank();
    }

    function testFuzzRejectsEveryOffCurvePublicKey(uint256 x, uint256 y) public {
        vm.assume(!P256Validation.isValidPublicKey(x, y));
        bytes memory validatorData = abi.encode(WebAuthnValidatorData(x, y), bytes32(0));
        bytes memory signerData = abi.encode(WebAuthnSignerData(x, y), bytes32(0));

        assertFalse(IStatelessValidator(address(validator)).validateSignatureWithData(bytes32(0), "", validatorData));
        assertFalse(IStatelessValidator(address(signer)).validateSignatureWithData(bytes32(0), "", signerData));

        vm.startPrank(ACCOUNT);
        vm.expectRevert(WebAuthnValidator.InvalidPublicKey.selector);
        validator.onInstall(validatorData);

        vm.expectRevert(WebAuthnSigner.InvalidPublicKey.selector);
        signer.onInstall(abi.encodePacked(bytes32(uint256(1)), signerData));
        vm.stopPrank();
    }

    function testAcceptsValidPublicKeyWithZeroCoordinate() public {
        bytes32 id = keccak256("zero-x WebAuthn signer id");
        bytes memory validatorData = abi.encode(WebAuthnValidatorData(0, ZERO_X_VALID_Y), bytes32(0));
        bytes memory signerData = abi.encode(WebAuthnSignerData(0, ZERO_X_VALID_Y), bytes32(0));

        vm.startPrank(ACCOUNT);
        validator.onInstall(validatorData);
        signer.onInstall(abi.encodePacked(id, signerData));
        vm.stopPrank();

        assertTrue(validator.isInitialized(ACCOUNT));
        assertTrue(signer.isInitialized(ACCOUNT));

        vm.startPrank(ACCOUNT);
        validator.onUninstall("");
        signer.onUninstall(abi.encodePacked(id));
        vm.stopPrank();
        assertFalse(validator.isInitialized(ACCOUNT));
        assertFalse(signer.isInitialized(ACCOUNT));
    }

    function testRejectsUnboundedResponseTypeLocationWithinGasLimit() public view {
        bytes32 hash = keccak256("bounded WebAuthn index");
        bytes memory signature = _withResponseTypeLocation(_signature(hash), type(uint128).max);

        bytes memory validatorCall =
            abi.encodeCall(IStatelessValidator.validateSignatureWithData, (hash, signature, _validatorData()));
        (bool validatorSuccess, bytes memory validatorResult) =
            address(validator).staticcall{gas: 150_000}(validatorCall);
        assertTrue(validatorSuccess);
        assertFalse(abi.decode(validatorResult, (bool)));

        bytes memory signerCall =
            abi.encodeCall(IStatelessValidator.validateSignatureWithData, (hash, signature, _signerData()));
        (bool signerSuccess, bytes memory signerResult) = address(signer).staticcall{gas: 150_000}(signerCall);
        assertTrue(signerSuccess);
        assertFalse(abi.decode(signerResult, (bool)));
    }

    function testFuzzRejectsEveryOutOfBoundsResponseTypeLocationWithinGasLimit(uint256 rawDelta) public view {
        bytes32 hash = keccak256("fuzzed bounded WebAuthn index");
        bytes memory originalSignature = _signature(hash);
        (, string memory clientDataJSON,,,,) =
            abi.decode(originalSignature, (bytes, string, uint256, uint256, uint256, bool));
        uint256 clientDataLength = bytes(clientDataJSON).length;
        uint256 delta = bound(rawDelta, 1, type(uint256).max - clientDataLength);
        bytes memory signature = _withResponseTypeLocation(originalSignature, clientDataLength + delta);

        bytes memory validatorCall =
            abi.encodeCall(IStatelessValidator.validateSignatureWithData, (hash, signature, _validatorData()));
        (bool validatorSuccess, bytes memory validatorResult) =
            address(validator).staticcall{gas: 150_000}(validatorCall);
        assertTrue(validatorSuccess);
        assertFalse(abi.decode(validatorResult, (bool)));

        bytes memory signerCall =
            abi.encodeCall(IStatelessValidator.validateSignatureWithData, (hash, signature, _signerData()));
        (bool signerSuccess, bytes memory signerResult) = address(signer).staticcall{gas: 150_000}(signerCall);
        assertTrue(signerSuccess);
        assertFalse(abi.decode(signerResult, (bool)));
    }

    function testFallsBackToDaimoWhenSoladyBackendsAreMissing() public {
        bytes32 hash = keccak256("Daimo WebAuthn fallback");
        bytes memory signature = _signature(hash);
        _mockMissingSoladyBackendsAndSuccessfulDaimo(signature);

        assertTrue(IStatelessValidator(address(validator)).validateSignatureWithData(hash, signature, _validatorData()));
        assertTrue(IStatelessValidator(address(signer)).validateSignatureWithData(hash, signature, _signerData()));
    }

    function testDaimoFallbackStillRequiresValidWebAuthnFields() public {
        bytes32 signedHash = keccak256("signed Daimo WebAuthn challenge");
        bytes32 requestedHash = keccak256("different Daimo WebAuthn challenge");
        bytes memory signature = _signature(signedHash);
        _mockMissingSoladyBackendsAndSuccessfulDaimo(signature);

        assertFalse(
            IStatelessValidator(address(validator))
                .validateSignatureWithData(requestedHash, signature, _validatorData())
        );
        assertFalse(
            IStatelessValidator(address(signer)).validateSignatureWithData(requestedHash, signature, _signerData())
        );
    }

    function testDaimoFallbackRejectsMalleableHighS() public {
        bytes32 hash = keccak256("high-s Daimo WebAuthn signature");
        bytes memory signature = _signature(hash);
        (,,,, uint256 s,) = abi.decode(signature, (bytes, string, uint256, uint256, uint256, bool));
        signature = _withS(signature, P256_N - s);
        _mockMissingSoladyBackendsAndSuccessfulDaimo(signature);

        assertFalse(
            IStatelessValidator(address(validator)).validateSignatureWithData(hash, signature, _validatorData())
        );
        assertFalse(IStatelessValidator(address(signer)).validateSignatureWithData(hash, signature, _signerData()));
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
        bytes32 messageHash = sha256(abi.encodePacked(authenticatorData, sha256(bytes(clientDataJSON))));
        (bytes32 r, bytes32 s) = vm.signP256(PRIVATE_KEY, messageHash);
        uint256 normalizedS = uint256(s);
        if (normalizedS > P256_N / 2) normalizedS = P256_N - normalizedS;

        return abi.encode(authenticatorData, clientDataJSON, responseTypeLocation, uint256(r), normalizedS, false);
    }

    function _withUsePrecompiled(bytes memory signature, bool usePrecompiled) internal pure returns (bytes memory) {
        (
            bytes memory authenticatorData,
            string memory clientDataJSON,
            uint256 responseTypeLocation,
            uint256 r,
            uint256 s,
        ) = abi.decode(signature, (bytes, string, uint256, uint256, uint256, bool));
        return abi.encode(authenticatorData, clientDataJSON, responseTypeLocation, r, s, usePrecompiled);
    }

    function _withResponseTypeLocation(bytes memory signature, uint256 responseTypeLocation)
        internal
        pure
        returns (bytes memory)
    {
        (bytes memory authenticatorData, string memory clientDataJSON,, uint256 r, uint256 s, bool usePrecompiled) =
            abi.decode(signature, (bytes, string, uint256, uint256, uint256, bool));
        return abi.encode(authenticatorData, clientDataJSON, responseTypeLocation, r, s, usePrecompiled);
    }

    function _withS(bytes memory signature, uint256 newS) internal pure returns (bytes memory) {
        (
            bytes memory authenticatorData,
            string memory clientDataJSON,
            uint256 responseTypeLocation,
            uint256 r,,
            bool usePrecompiled
        ) = abi.decode(signature, (bytes, string, uint256, uint256, uint256, bool));
        return abi.encode(authenticatorData, clientDataJSON, responseTypeLocation, r, newS, usePrecompiled);
    }

    function _mockMissingSoladyBackendsAndSuccessfulDaimo(bytes memory signature) internal {
        (bytes memory authenticatorData, string memory clientDataJSON,, uint256 r, uint256 s,) =
            abi.decode(signature, (bytes, string, uint256, uint256, uint256, bool));

        bytes32 messageHash = sha256(abi.encodePacked(authenticatorData, sha256(bytes(clientDataJSON))));
        bytes memory verificationInput = abi.encode(messageHash, r, s, pubKeyX, pubKeyY);
        bytes memory probeInput = abi.encode(
            bytes32(0x532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25),
            uint256(5),
            uint256(1),
            uint256(0x4a03ef9f92eb268cafa601072489a56380fa0dc43171d7712813b3a19a1eb5e5),
            uint256(0x3e213e28a608ce9a2f4a17fd830c6654018a79b3e0263d91a8ba90622df6f2f0)
        );

        vm.etch(SOLADY_VERIFIER, hex"");
        vm.etch(SOLADY_CANARY, hex"");
        vm.mockCall(P256_PRECOMPILE, verificationInput, hex"");
        vm.mockCall(P256_PRECOMPILE, probeInput, hex"");
        vm.mockCall(DAIMO_VERIFIER, verificationInput, abi.encode(uint256(1)));
    }
}
