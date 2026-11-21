// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {IValidator, IStatelessValidator, IStatelessValidatorWithSender} from "src/interfaces/IERC7579Modules.sol";
import {
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_STATELESS_VALIDATOR,
    MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER
} from "src/types/Constants.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {
    SIG_VALIDATION_FAILED_UINT,
    SIG_VALIDATION_SUCCESS_UINT,
    ERC1271_MAGICVALUE,
    ERC1271_INVALID
} from "src/types/Constants.sol";
import {P256Validation} from "src/utils/P256Validation.sol";
import {WebAuthnValidation} from "src/utils/WebAuthnValidation.sol";

struct WebAuthnValidatorData {
    uint256 pubKeyX;
    uint256 pubKeyY;
}

/**
 * @title WebAuthnValidator
 * @notice This validator uses the P256 curve to validate signatures.
 */
contract WebAuthnValidator is IValidator, IStatelessValidator, IStatelessValidatorWithSender {
    // Emitted when a bad key is provided.
    error InvalidPublicKey();

    // Emitted when the public key of a kernel is changed.
    event WebAuthnRegistered(address indexed kernel, uint256 pubKeyX, uint256 pubKeyY);

    // The P256 public keys of a kernel.
    mapping(address kernel => WebAuthnValidatorData WebAuthnValidatorData) public webAuthnValidatorStorage;

    /**
     * @notice Install WebAuthn validator for a kernel account.
     * @dev The kernel account need to be the `msg.sender`.
     * @dev `_data` must contain the 96-byte encoding
     *      `abi.encode(WebAuthnValidatorData(pubKeyX, pubKeyY), bytes32 authenticatorIdHash)`.
     */
    function onInstall(bytes calldata _data) external payable override {
        // check if the webauthn validator is already initialized
        if (_isInitialized(msg.sender)) revert AlreadyInitialized(msg.sender);
        // check validity of the public key
        (WebAuthnValidatorData memory webAuthnData,) = abi.decode(_data, (WebAuthnValidatorData, bytes32));
        if (!P256Validation.isValidPublicKey(webAuthnData.pubKeyX, webAuthnData.pubKeyY)) {
            revert InvalidPublicKey();
        }
        // Update the key (so a sstore)
        webAuthnValidatorStorage[msg.sender] = webAuthnData;
        // And emit the event
        emit WebAuthnRegistered(msg.sender, webAuthnData.pubKeyX, webAuthnData.pubKeyY);
    }

    /**
     * @notice Uninstall WebAuthn validator for a kernel account.
     * @dev The kernel account need to be the `msg.sender`.
     */
    function onUninstall(bytes calldata) external payable override {
        if (!_isInitialized(msg.sender)) revert NotInitialized(msg.sender);
        delete webAuthnValidatorStorage[msg.sender];
    }

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_VALIDATOR || typeID == MODULE_TYPE_STATELESS_VALIDATOR
            || typeID == MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER;
    }

    function isInitialized(address smartAccount) external view returns (bool) {
        return _isInitialized(smartAccount);
    }

    function _isInitialized(address smartAccount) internal view returns (bool) {
        WebAuthnValidatorData storage key = webAuthnValidatorStorage[smartAccount];
        return key.pubKeyX != 0 || key.pubKeyY != 0;
    }

    /**
     * @notice Validate a user operation.
     */
    function validateUserOp(PackedUserOperation calldata _userOp, bytes32 _userOpHash)
        external
        payable
        override
        returns (uint256)
    {
        return _verifySignature(_userOpHash, _userOp.signature, webAuthnValidatorStorage[msg.sender]);
    }

    /**
     * @notice Verify a signature with sender for ERC-1271 validation.
     */
    function isValidSignatureWithSender(address, bytes32 hash, bytes calldata data) external view returns (bytes4) {
        return _verifySignature(hash, data, webAuthnValidatorStorage[msg.sender]) == SIG_VALIDATION_SUCCESS_UINT
            ? ERC1271_MAGICVALUE
            : ERC1271_INVALID;
    }

    function validateSignatureWithData(bytes32 hash, bytes calldata signature, bytes calldata data)
        external
        view
        override
        returns (bool)
    {
        return _verifyStatelessSignature(hash, signature, data);
    }

    function validateSignatureWithDataWithSender(address, bytes32 hash, bytes calldata signature, bytes calldata data)
        external
        view
        override
        returns (bool)
    {
        return _verifyStatelessSignature(hash, signature, data);
    }

    /**
     * @notice Verify a signature.
     * @dev `signature` is the legacy encoding
     *      `abi.encode(authenticatorData, clientDataJSON, responseTypeLocation, r, s, usePrecompiled)`.
     *      `usePrecompiled` is retained for ABI compatibility and ignored.
     * @dev Virtual to let formal-verification harnesses model only the cryptographic boundary.
     */
    function _verifySignature(bytes32 hash, bytes calldata signature, WebAuthnValidatorData memory webAuthnData)
        internal
        view
        virtual
        returns (uint256)
    {
        // decode the signature
        (
            bytes memory authenticatorData,
            string memory clientDataJSON,
            uint256 responseTypeLocation,
            uint256 r,
            uint256 s,
            /* usePrecompiled */
        ) = abi.decode(signature, (bytes, string, uint256, uint256, uint256, bool));

        bool isValid = WebAuthnValidation.verify(
            hash,
            authenticatorData,
            clientDataJSON,
            responseTypeLocation,
            r,
            s,
            webAuthnData.pubKeyX,
            webAuthnData.pubKeyY
        );

        // return the validation data
        if (isValid) {
            return SIG_VALIDATION_SUCCESS_UINT;
        }

        return SIG_VALIDATION_FAILED_UINT;
    }

    function _verifyStatelessSignature(bytes32 hash, bytes calldata signature, bytes calldata data)
        private
        view
        returns (bool)
    {
        if (data.length != 96) return false;
        (WebAuthnValidatorData memory webAuthnData,) = abi.decode(data, (WebAuthnValidatorData, bytes32));
        if (!P256Validation.isValidPublicKey(webAuthnData.pubKeyX, webAuthnData.pubKeyY)) return false;
        return _verifySignature(hash, signature, webAuthnData) == SIG_VALIDATION_SUCCESS_UINT;
    }
}
