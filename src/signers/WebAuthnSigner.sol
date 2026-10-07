// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {SignerBase} from "src/base/SignerBase.sol";
import {IModule, IStatelessValidator, IStatelessValidatorWithSender} from "src/interfaces/IERC7579Modules.sol";
import {
    SIG_VALIDATION_SUCCESS_UINT,
    SIG_VALIDATION_FAILED_UINT,
    MODULE_TYPE_SIGNER,
    MODULE_TYPE_STATELESS_VALIDATOR,
    MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER
} from "src/types/Constants.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {ERC1271_MAGICVALUE, ERC1271_INVALID} from "src/types/Constants.sol";
import {P256Validation} from "src/utils/P256Validation.sol";
import {WebAuthnValidation} from "src/utils/WebAuthnValidation.sol";

struct WebAuthnSignerData {
    uint256 pubKeyX;
    uint256 pubKeyY;
}

/**
 * @title WebAuthnSigner
 * @notice This signer uses the P256 curve to validate signatures.
 */
contract WebAuthnSigner is SignerBase, IStatelessValidator, IStatelessValidatorWithSender {
    // Emitted when a bad key is provided.
    error InvalidPublicKey();

    // Emitted when the public key of a kernel is changed.
    event WebAuthnRegistered(address indexed kernel, uint256 pubKeyX, uint256 pubKeyY);

    mapping(address => uint256) public usedIds;
    // The P256 public keys of a kernel.
    mapping(bytes32 id => mapping(address kernel => WebAuthnSignerData)) public webAuthnSignerStorage;

    function isModuleType(uint256 typeID) external pure override(IModule, SignerBase) returns (bool) {
        return typeID == MODULE_TYPE_SIGNER || typeID == MODULE_TYPE_STATELESS_VALIDATOR
            || typeID == MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER;
    }

    function isInitialized(address kernel) external view returns (bool) {
        return _isInitialized(kernel);
    }

    function _isInitialized(address kernel) internal view returns (bool) {
        return usedIds[kernel] > 0;
    }

    /**
     * @notice Validate a user operation.
     */
    function checkUserOpSignature(bytes32 id, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        override
        returns (uint256)
    {
        return _verifySignature(userOpHash, userOp.signature, webAuthnSignerStorage[id][msg.sender]);
    }

    /**
     * @notice Verify a signature with sender for ERC-1271 validation.
     */
    function checkSignature(bytes32 id, address, bytes32 hash, bytes calldata sig)
        external
        view
        override
        returns (bytes4)
    {
        return _verifySignature(hash, sig, webAuthnSignerStorage[id][msg.sender]) == SIG_VALIDATION_SUCCESS_UINT
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
    function _verifySignature(bytes32 hash, bytes calldata signature, WebAuthnSignerData memory webAuthnData)
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
        (WebAuthnSignerData memory webAuthnData,) = abi.decode(data, (WebAuthnSignerData, bytes32));
        if (!P256Validation.isValidPublicKey(webAuthnData.pubKeyX, webAuthnData.pubKeyY)) return false;
        return _verifySignature(hash, signature, webAuthnData) == SIG_VALIDATION_SUCCESS_UINT;
    }
    /**
     * @notice Install WebAuthn signer for a kernel account.
     * @dev The kernel account need to be the `msg.sender`.
     * @dev The `_data` suffix after the 32-byte permission ID must contain the 96-byte encoding
     *      `abi.encode(WebAuthnSignerData(pubKeyX, pubKeyY), bytes32 authenticatorIdHash)`.
     */

    function _signerOninstall(bytes32 id, bytes calldata _data) internal override {
        // check if this specific id is already initialized
        if (webAuthnSignerStorage[id][msg.sender].pubKeyX != 0 || webAuthnSignerStorage[id][msg.sender].pubKeyY != 0) {
            revert AlreadyInitialized(msg.sender);
        }
        usedIds[msg.sender]++;
        // check validity of the public key
        (WebAuthnSignerData memory webAuthnData,) = abi.decode(_data, (WebAuthnSignerData, bytes32));
        if (!P256Validation.isValidPublicKey(webAuthnData.pubKeyX, webAuthnData.pubKeyY)) {
            revert InvalidPublicKey();
        }
        // Update the key (so a sstore)
        webAuthnSignerStorage[id][msg.sender] = webAuthnData;
        // And emit the event
        emit WebAuthnRegistered(msg.sender, webAuthnData.pubKeyX, webAuthnData.pubKeyY);
    }

    /**
     * @notice Uninstall WebAuthn validator for a kernel account.
     * @dev The kernel account need to be the `msg.sender`.
     */
    function _signerOnUninstall(bytes32 id, bytes calldata) internal override {
        // check if this specific id is initialized
        if (webAuthnSignerStorage[id][msg.sender].pubKeyX == 0 && webAuthnSignerStorage[id][msg.sender].pubKeyY == 0) {
            revert NotInitialized(msg.sender);
        }
        delete webAuthnSignerStorage[id][msg.sender];
        usedIds[msg.sender]--;
    }
}
