// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

import {IModule, IStatelessValidator} from "src/interfaces/IERC7579Modules.sol";
import {ECDSASigner} from "src/signers/ECDSASigner.sol";
import {P256Signer} from "src/signers/P256Signer.sol";
import {WebAuthnSigner, WebAuthnSignerData} from "src/signers/WebAuthnSigner.sol";
import {
    ERC1271_INVALID,
    ERC1271_MAGICVALUE,
    MODULE_TYPE_STATELESS_VALIDATOR,
    SIG_VALIDATION_FAILED_UINT
} from "src/types/Constants.sol";
import {MultiOwnerValidator} from "src/validators/MultiOwnerValidator.sol";
import {Base64} from "solady/utils/Base64.sol";
import {ValidatorTestBase} from "test/base/ValidatorTestBase.sol";

contract ArbitraryStatelessSigner is IStatelessValidator {
    function onInstall(bytes calldata) external payable {}

    function onUninstall(bytes calldata) external payable {}

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_STATELESS_VALIDATOR;
    }

    function validateSignatureWithData(bytes32 hash, bytes calldata signature, bytes calldata data)
        external
        pure
        returns (bool)
    {
        return keccak256(signature) == keccak256(abi.encodePacked(hash, data));
    }
}

contract RevertingStatelessSigner is IStatelessValidator {
    function onInstall(bytes calldata) external payable {}

    function onUninstall(bytes calldata) external payable {}

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_STATELESS_VALIDATOR;
    }

    function validateSignatureWithData(bytes32, bytes calldata, bytes calldata) external pure returns (bool) {
        revert("validation reverted");
    }
}

contract NonStatelessModule is IModule {
    function onInstall(bytes calldata) external payable {}

    function onUninstall(bytes calldata) external payable {}

    function isModuleType(uint256) external pure returns (bool) {
        return false;
    }
}

contract MultiOwnerValidatorTest is ValidatorTestBase {
    uint256 internal constant P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    uint256 internal constant ECDSA_KEY = 0xA11CE;
    uint256 internal constant P256_KEY = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;

    bytes32 internal constant ECDSA_ID = keccak256("ecdsa-owner");
    bytes32 internal constant P256_ID = keccak256("p256-owner");
    bytes32 internal constant WEBAUTHN_ID = keccak256("webauthn-owner");
    bytes32 internal constant ARBITRARY_ID = keccak256("arbitrary-owner");

    MultiOwnerValidator internal validator;
    ECDSASigner internal ecdsaSigner;
    P256Signer internal p256Signer;
    WebAuthnSigner internal webAuthnSigner;
    ArbitraryStatelessSigner internal arbitrarySigner;
    RevertingStatelessSigner internal revertingSigner;
    NonStatelessModule internal nonStatelessModule;

    address internal ecdsaOwner;
    uint256 internal p256X;
    uint256 internal p256Y;

    function deployModule() internal override returns (IModule) {
        validator = new MultiOwnerValidator();
        return validator;
    }

    function _initializeTest() internal override {
        ecdsaSigner = new ECDSASigner();
        p256Signer = new P256Signer();
        webAuthnSigner = new WebAuthnSigner();
        arbitrarySigner = new ArbitraryStatelessSigner();
        revertingSigner = new RevertingStatelessSigner();
        nonStatelessModule = new NonStatelessModule();

        ecdsaOwner = vm.addr(ECDSA_KEY);
        (p256X, p256Y) = vm.publicKeyP256(P256_KEY);
    }

    function installData() internal view override returns (bytes memory) {
        MultiOwnerValidator.OwnerConfig[] memory configs = new MultiOwnerValidator.OwnerConfig[](1);
        configs[0] = _ecdsaConfig(ECDSA_ID, ecdsaOwner);
        return abi.encode(configs);
    }

    function userOpSignature(PackedUserOperation memory userOp, bool valid)
        internal
        view
        override
        returns (bytes memory)
    {
        bytes32 hash = ENTRYPOINT.getUserOpHash(userOp);
        return abi.encodePacked(ECDSA_ID, _ecdsaSignature(valid ? hash : keccak256(abi.encode("invalid", hash))));
    }

    function erc1271Signature(bytes32 hash, bool valid)
        internal
        pure
        override
        returns (address sender, bytes memory signature)
    {
        bytes32 signedHash = valid ? hash : keccak256(abi.encode("invalid", hash));
        return (address(0), abi.encodePacked(ECDSA_ID, _ecdsaSignature(signedHash)));
    }

    function _afterInstallCheck() internal view override {
        assertTrue(validator.isInitialized(WALLET));
        assertEq(validator.ownerCount(WALLET), 1);
        assertEq(validator.ownerIdAt(WALLET, 0), ECDSA_ID);
        (address statelessValidator, bytes memory validationData) = validator.owners(WALLET, ECDSA_ID);
        assertEq(statelessValidator, address(ecdsaSigner));
        assertEq(validationData, abi.encodePacked(ecdsaOwner));
    }

    function _afterUninstallCheck() internal view override {
        assertFalse(validator.isInitialized(WALLET));
        assertEq(validator.ownerCount(WALLET), 0);
        (address statelessValidator, bytes memory validationData) = validator.owners(WALLET, ECDSA_ID);
        assertEq(statelessValidator, address(0));
        assertEq(validationData.length, 0);
    }

    function testInstallSupportsAnyStatelessSigner() public {
        MultiOwnerValidator.OwnerConfig[] memory configs = new MultiOwnerValidator.OwnerConfig[](4);
        configs[0] = _ecdsaConfig(ECDSA_ID, ecdsaOwner);
        configs[1] = _p256Config(P256_ID);
        configs[2] = _webAuthnConfig(WEBAUTHN_ID);
        configs[3] = _config(ARBITRARY_ID, address(arbitrarySigner), hex"c0ffee");

        vm.prank(WALLET);
        validator.onInstall(abi.encode(configs));

        assertEq(validator.ownerCount(WALLET), 4);
        assertEq(validator.ownerIdAt(WALLET, 0), ECDSA_ID);
        assertEq(validator.ownerIdAt(WALLET, 1), P256_ID);
        assertEq(validator.ownerIdAt(WALLET, 2), WEBAUTHN_ID);
        assertEq(validator.ownerIdAt(WALLET, 3), ARBITRARY_ID);
    }

    function testInstallRejectsEmptyOwnerSet() public {
        MultiOwnerValidator.OwnerConfig[] memory configs = new MultiOwnerValidator.OwnerConfig[](0);
        vm.prank(WALLET);
        vm.expectRevert(MultiOwnerValidator.EmptyOwners.selector);
        validator.onInstall(abi.encode(configs));
    }

    function testInstallRejectsDuplicateOwnerIds() public {
        MultiOwnerValidator.OwnerConfig[] memory configs = new MultiOwnerValidator.OwnerConfig[](2);
        configs[0] = _ecdsaConfig(ECDSA_ID, ecdsaOwner);
        configs[1] = _p256Config(ECDSA_ID);

        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(MultiOwnerValidator.OwnerAlreadyExists.selector, ECDSA_ID));
        validator.onInstall(abi.encode(configs));
    }

    function testInstallRejectsInvalidOwnerConfigurations() public {
        _expectInvalidConfig(
            _config(bytes32(0), address(ecdsaSigner), abi.encodePacked(ecdsaOwner)),
            MultiOwnerValidator.InvalidOwnerId.selector
        );
        _expectInvalidConfig(
            _config(ECDSA_ID, address(0), abi.encodePacked(ecdsaOwner)),
            abi.encodeWithSelector(MultiOwnerValidator.InvalidStatelessValidator.selector, address(0))
        );
        _expectInvalidConfig(
            _config(ECDSA_ID, ecdsaOwner, abi.encodePacked(ecdsaOwner)),
            abi.encodeWithSelector(MultiOwnerValidator.InvalidStatelessValidator.selector, ecdsaOwner)
        );
        _expectInvalidConfig(
            _config(ECDSA_ID, address(nonStatelessModule), abi.encodePacked(ecdsaOwner)),
            abi.encodeWithSelector(MultiOwnerValidator.InvalidStatelessValidator.selector, address(nonStatelessModule))
        );
    }

    function testAddUpdateAndRemoveOwners() public {
        _installDefault();

        vm.prank(WALLET);
        validator.addOwner(_p256Config(P256_ID));
        assertEq(validator.ownerCount(WALLET), 2);

        MultiOwnerValidator.OwnerConfig memory updated = _webAuthnConfig(P256_ID);
        vm.prank(WALLET);
        validator.updateOwner(updated);
        (address statelessValidator, bytes memory validationData) = validator.owners(WALLET, P256_ID);
        assertEq(statelessValidator, address(webAuthnSigner));
        assertEq(validationData, _webAuthnData());
        assertEq(validator.ownerCount(WALLET), 2);

        vm.prank(WALLET);
        validator.removeOwner(ECDSA_ID);
        assertEq(validator.ownerCount(WALLET), 1);
        assertEq(validator.ownerIdAt(WALLET, 0), P256_ID);
        (statelessValidator, validationData) = validator.owners(WALLET, ECDSA_ID);
        assertEq(statelessValidator, address(0));
        assertEq(validationData.length, 0);
    }

    function testCannotRemoveLastOwner() public {
        _installDefault();
        vm.prank(WALLET);
        vm.expectRevert(MultiOwnerValidator.CannotRemoveLastOwner.selector);
        validator.removeOwner(ECDSA_ID);
    }

    function testLifecycleOperationsRequireInitializedCaller() public {
        vm.startPrank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IModule.NotInitialized.selector, WALLET));
        validator.addOwner(_ecdsaConfig(ECDSA_ID, ecdsaOwner));
        vm.expectRevert(abi.encodeWithSelector(IModule.NotInitialized.selector, WALLET));
        validator.updateOwner(_ecdsaConfig(ECDSA_ID, ecdsaOwner));
        vm.expectRevert(abi.encodeWithSelector(IModule.NotInitialized.selector, WALLET));
        validator.removeOwner(ECDSA_ID);
        vm.stopPrank();
    }

    function testAccountStorageIsIsolated() public {
        _installDefault();
        address otherAccount = address(0xBEEF);
        address otherOwner = vm.addr(0xB0B);
        MultiOwnerValidator.OwnerConfig[] memory configs = new MultiOwnerValidator.OwnerConfig[](1);
        configs[0] = _ecdsaConfig(ECDSA_ID, otherOwner);

        vm.prank(otherAccount);
        validator.onInstall(abi.encode(configs));

        (, bytes memory walletData) = validator.owners(WALLET, ECDSA_ID);
        (, bytes memory otherAccountData) = validator.owners(otherAccount, ECDSA_ID);
        assertEq(walletData, abi.encodePacked(ecdsaOwner));
        assertEq(otherAccountData, abi.encodePacked(otherOwner));
    }

    function testUninstallClearsEveryOwnerAndAllowsReinstall() public {
        _installDefault();
        vm.prank(WALLET);
        validator.addOwner(_p256Config(P256_ID));

        vm.prank(WALLET);
        validator.onUninstall("");
        assertEq(validator.ownerCount(WALLET), 0);
        (address ecdsaModule,) = validator.owners(WALLET, ECDSA_ID);
        (address p256Module,) = validator.owners(WALLET, P256_ID);
        assertEq(ecdsaModule, address(0));
        assertEq(p256Module, address(0));

        vm.prank(WALLET);
        validator.onInstall(installData());
        assertEq(validator.ownerCount(WALLET), 1);
    }

    function testDelegatesToECDSAStatelessSigner() public {
        _installDefault();
        bytes32 hash = keccak256("ECDSA stateless owner");
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
        bytes memory signature = abi.encodePacked(ECDSA_ID, _ecdsaSignature(ethHash));

        vm.prank(WALLET);
        assertEq(validator.isValidSignatureWithSender(address(0), hash, signature), ERC1271_MAGICVALUE);
    }

    function testDelegatesToP256StatelessSigner() public {
        _installDefault();
        vm.prank(WALLET);
        validator.addOwner(_p256Config(P256_ID));

        bytes32 hash = keccak256("P256 stateless owner");
        bytes memory signature = abi.encodePacked(P256_ID, _p256Signature(hash));
        vm.prank(WALLET);
        assertEq(validator.isValidSignatureWithSender(address(0), hash, signature), ERC1271_MAGICVALUE);
    }

    function testDelegatesToWebAuthnStatelessSignerWithDynamicLocations() public {
        _installDefault();
        vm.prank(WALLET);
        validator.addOwner(_webAuthnConfig(WEBAUTHN_ID));

        bytes32 hash = keccak256("dynamic WebAuthn locations");
        bytes memory webAuthnSignature = _webAuthnSignature(hash, '{"origin":"https://example.com",');
        (
            bytes memory authenticatorData,
            string memory clientDataJSON,
            uint256 challengeLocation,
            uint256 responseTypeLocation,
            uint256 r,
            uint256 s
        ) = abi.decode(webAuthnSignature, (bytes, string, uint256, uint256, uint256, uint256));
        assertNotEq(challengeLocation, 23);

        vm.prank(WALLET);
        assertEq(
            validator.isValidSignatureWithSender(address(0), hash, abi.encodePacked(WEBAUTHN_ID, webAuthnSignature)),
            ERC1271_MAGICVALUE
        );

        bytes memory wrongLocationSignature =
            abi.encode(authenticatorData, clientDataJSON, uint256(23), responseTypeLocation, r, s);
        vm.prank(WALLET);
        assertEq(
            validator.isValidSignatureWithSender(
                address(0), hash, abi.encodePacked(WEBAUTHN_ID, wrongLocationSignature)
            ),
            ERC1271_INVALID
        );
    }

    function testDelegatesToArbitraryStatelessSigner() public {
        bytes memory validationData = hex"c0ffee";
        MultiOwnerValidator.OwnerConfig[] memory configs = new MultiOwnerValidator.OwnerConfig[](1);
        configs[0] = _config(ARBITRARY_ID, address(arbitrarySigner), validationData);
        vm.prank(WALLET);
        validator.onInstall(abi.encode(configs));

        bytes32 hash = keccak256("arbitrary signer");
        bytes memory ownerSignature = abi.encodePacked(hash, validationData);
        vm.prank(WALLET);
        assertEq(
            validator.isValidSignatureWithSender(address(0), hash, abi.encodePacked(ARBITRARY_ID, ownerSignature)),
            ERC1271_MAGICVALUE
        );
    }

    function testSelectedOwnerDefinesSignatureFormat() public {
        _installDefault();
        vm.prank(WALLET);
        validator.addOwner(_p256Config(P256_ID));

        bytes32 hash = keccak256("validator binding");
        bytes memory ecdsaUnderP256Id = abi.encodePacked(P256_ID, _ecdsaSignature(hash));
        bytes memory p256UnderECDSAId = abi.encodePacked(ECDSA_ID, _p256Signature(hash));

        vm.startPrank(WALLET);
        assertEq(validator.isValidSignatureWithSender(address(0), hash, ecdsaUnderP256Id), ERC1271_INVALID);
        assertEq(validator.isValidSignatureWithSender(address(0), hash, p256UnderECDSAId), ERC1271_INVALID);
        vm.stopPrank();
    }

    function testRemovedAndUnknownOwnersFail() public {
        _installDefault();
        vm.prank(WALLET);
        validator.addOwner(_p256Config(P256_ID));
        vm.prank(WALLET);
        validator.removeOwner(ECDSA_ID);

        bytes32 hash = keccak256("removed owner");
        vm.startPrank(WALLET);
        assertEq(
            validator.isValidSignatureWithSender(address(0), hash, abi.encodePacked(ECDSA_ID, _ecdsaSignature(hash))),
            ERC1271_INVALID
        );
        assertEq(
            validator.isValidSignatureWithSender(
                address(0), hash, abi.encodePacked(bytes32(uint256(0xBAD)), _ecdsaSignature(hash))
            ),
            ERC1271_INVALID
        );
        vm.stopPrank();
    }

    function testMalformedOrRevertingChildValidationFailsWithoutReverting() public {
        _installDefault();
        vm.prank(WALLET);
        validator.addOwner(_config(ARBITRARY_ID, address(revertingSigner), ""));

        bytes32 hash = keccak256("malformed signatures");
        vm.startPrank(WALLET);
        assertEq(validator.isValidSignatureWithSender(address(0), hash, hex""), ERC1271_INVALID);
        assertEq(
            validator.isValidSignatureWithSender(address(0), hash, abi.encodePacked(ECDSA_ID, hex"01")), ERC1271_INVALID
        );
        assertEq(
            validator.isValidSignatureWithSender(address(0), hash, abi.encodePacked(ARBITRARY_ID, hex"01")),
            ERC1271_INVALID
        );
        vm.stopPrank();
    }

    function testValidateUserOpRejectsMismatchedAccount() public {
        _installDefault();
        PackedUserOperation memory userOp;
        userOp.sender = address(0xBEEF);
        userOp.signature = abi.encodePacked(ECDSA_ID, _ecdsaSignature(bytes32(uint256(1))));

        vm.prank(WALLET);
        assertEq(validator.validateUserOp(userOp, bytes32(uint256(1))), SIG_VALIDATION_FAILED_UINT);
    }

    function testUpdatingOwnerImmediatelyChangesDelegatedSigner() public {
        _installDefault();
        uint256 newKey = 0xB0B;
        address newOwner = vm.addr(newKey);
        vm.prank(WALLET);
        validator.updateOwner(_ecdsaConfig(ECDSA_ID, newOwner));

        bytes32 hash = keccak256("key rotation");
        bytes memory oldSignature = abi.encodePacked(ECDSA_ID, _ecdsaSignature(hash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(newKey, hash);
        bytes memory newSignature = abi.encodePacked(ECDSA_ID, r, s, v);

        vm.startPrank(WALLET);
        assertEq(validator.isValidSignatureWithSender(address(0), hash, oldSignature), ERC1271_INVALID);
        assertEq(validator.isValidSignatureWithSender(address(0), hash, newSignature), ERC1271_MAGICVALUE);
        vm.stopPrank();
    }

    function _installDefault() internal {
        vm.prank(WALLET);
        validator.onInstall(installData());
    }

    function _expectInvalidConfig(MultiOwnerValidator.OwnerConfig memory config, bytes memory expectedError) internal {
        MultiOwnerValidator.OwnerConfig[] memory configs = new MultiOwnerValidator.OwnerConfig[](1);
        configs[0] = config;
        vm.prank(WALLET);
        vm.expectRevert(expectedError);
        validator.onInstall(abi.encode(configs));
    }

    function _expectInvalidConfig(MultiOwnerValidator.OwnerConfig memory config, bytes4 expectedError) internal {
        MultiOwnerValidator.OwnerConfig[] memory configs = new MultiOwnerValidator.OwnerConfig[](1);
        configs[0] = config;
        vm.prank(WALLET);
        vm.expectRevert(expectedError);
        validator.onInstall(abi.encode(configs));
    }

    function _config(bytes32 ownerId, address statelessValidator, bytes memory validationData)
        internal
        pure
        returns (MultiOwnerValidator.OwnerConfig memory)
    {
        return MultiOwnerValidator.OwnerConfig(ownerId, statelessValidator, validationData);
    }

    function _ecdsaConfig(bytes32 ownerId, address owner)
        internal
        view
        returns (MultiOwnerValidator.OwnerConfig memory)
    {
        return _config(ownerId, address(ecdsaSigner), abi.encodePacked(owner));
    }

    function _p256Config(bytes32 ownerId) internal view returns (MultiOwnerValidator.OwnerConfig memory) {
        return _config(ownerId, address(p256Signer), abi.encode(p256X, p256Y));
    }

    function _webAuthnConfig(bytes32 ownerId) internal view returns (MultiOwnerValidator.OwnerConfig memory) {
        return _config(ownerId, address(webAuthnSigner), _webAuthnData());
    }

    function _webAuthnData() internal view returns (bytes memory) {
        return abi.encode(WebAuthnSignerData(p256X, p256Y), bytes32(0));
    }

    function _ecdsaSignature(bytes32 hash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ECDSA_KEY, hash);
        return abi.encodePacked(r, s, v);
    }

    function _p256Signature(bytes32 hash) internal pure returns (bytes memory) {
        (bytes32 r, bytes32 s) = vm.signP256(P256_KEY, hash);
        uint256 normalizedS = uint256(s);
        if (normalizedS > P256_N / 2) normalizedS = P256_N - normalizedS;
        return abi.encode(r, bytes32(normalizedS));
    }

    function _webAuthnSignature(bytes32 hash, string memory clientDataPrefix) internal pure returns (bytes memory) {
        bytes memory authenticatorData = new bytes(37);
        authenticatorData[32] = bytes1(uint8(0x05));

        string memory challenge = Base64.encode(abi.encodePacked(hash), true, true);
        string memory clientDataJSON =
            string.concat(clientDataPrefix, '"type":"webauthn.get",', '"challenge":"', challenge, '"}');
        uint256 responseTypeLocation = bytes(clientDataPrefix).length;
        uint256 challengeLocation = responseTypeLocation + 22;
        bytes32 messageHash = sha256(abi.encodePacked(authenticatorData, sha256(bytes(clientDataJSON))));
        (bytes32 r, bytes32 s) = vm.signP256(P256_KEY, messageHash);
        uint256 normalizedS = uint256(s);
        if (normalizedS > P256_N / 2) normalizedS = P256_N - normalizedS;

        return
            abi.encode(
                authenticatorData, clientDataJSON, challengeLocation, responseTypeLocation, uint256(r), normalizedS
            );
    }
}
