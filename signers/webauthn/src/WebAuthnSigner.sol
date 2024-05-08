// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "kernel/sdk/moduleBase/SignerBase.sol";
import {VALIDATION_SUCCESS, VALIDATION_FAILED} from "kernel/interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "kernel/interfaces/PackedUserOperation.sol";
import {ERC1271_MAGICVALUE, ERC1271_INVALID} from "kernel/types/Constants.sol";
import {WebAuthn} from "./WebAuthn.sol";

struct WebAuthnSignerData {
    uint256 pubKeyX;
    uint256 pubKeyY;
}

/**
 * @title WebAuthnSigner
 * @notice This signer uses the P256 curve to validate signatures.
 */
contract WebAuthnSigner is SignerBase {
    // The location of the challenge in the clientDataJSON
    uint256 constant CHALLENGE_LOCATION = 23;

    // Emitted when a bad key is provided.
    error InvalidPublicKey();

    // Emitted when the public key of a kernel is changed.
    event WebAuthnPublicKeyRegistered(
        address indexed kernel, bytes32 indexed authenticatorIdHash, uint256 pubKeyX, uint256 pubKeyY
    );

    mapping(address => uint256) public usedIds;
    // The P256 public keys of a kernel.
    mapping(bytes32 id => mapping(address kernel => WebAuthnSignerData)) public webAuthnSignerStorage;

    function isInitialized(address kernel) external view override returns (bool) {
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
        return _verifySignature(id, userOp.sender, userOpHash, userOp.signature);
    }

    /**
     * @notice Verify a signature with sender for ERC-1271 validation.
     */
    function checkSignature(bytes32 id, address sender, bytes32 hash, bytes calldata sig)
        external
        view
        override
        returns (bytes4)
    {
        return _verifySignature(id, sender, hash, sig) == VALIDATION_SUCCESS ? ERC1271_MAGICVALUE : ERC1271_INVALID;
    }

    /**
     * @notice Verify a signature.
     */
    function _verifySignature(bytes32 id, address sender, bytes32 hash, bytes calldata signature)
        private
        view
        returns (uint256)
    {
        // decode the signature
        (
            bytes memory authenticatorData,
            string memory clientDataJSON,
            uint256 responseTypeLocation,
            uint256 r,
            uint256 s,
            bool usePrecompiled
        ) = abi.decode(signature, (bytes, string, uint256, uint256, uint256, bool));

        // get the public key from storage
        WebAuthnSignerData memory webAuthnData = webAuthnSignerStorage[id][msg.sender];

        // verify the signature using the signature and the public key
        bool isValid = WebAuthn.verifySignature(
            abi.encodePacked(hash),
            authenticatorData,
            true,
            clientDataJSON,
            CHALLENGE_LOCATION,
            responseTypeLocation,
            r,
            s,
            webAuthnData.pubKeyX,
            webAuthnData.pubKeyY,
            usePrecompiled
        );

        // return the validation data
        if (isValid) {
            return VALIDATION_SUCCESS;
        }

        return VALIDATION_FAILED;
    }
    /**
     * @notice Install WebAuthn signer for a kernel account.
     * @dev The kernel account need to be the `msg.sender`.
     * @dev The public key is encoded as `abi.encode(WebAuthnSignerData)` inside the data, so (uint256,uint256).
     * @dev The authenticatorIdHash is the hash of the authenticatorId. It enables to find public keys on-chain via event logs.
     */

    function _signerOninstall(bytes32 id, bytes calldata _data) internal override {
        // check if the webauthn validator is already initialized
        if (_isInitialized(msg.sender)) revert AlreadyInitialized(msg.sender);
        usedIds[msg.sender]++;
        // check validity of the public key
        (WebAuthnSignerData memory webAuthnData, bytes32 authenticatorIdHash) =
            abi.decode(_data, (WebAuthnSignerData, bytes32));
        if (webAuthnData.pubKeyX == 0 || webAuthnData.pubKeyY == 0) {
            revert InvalidPublicKey();
        }
        // Update the key (so a sstore)
        webAuthnSignerStorage[id][msg.sender] = webAuthnData;
        // And emit the event
        emit WebAuthnPublicKeyRegistered(msg.sender, authenticatorIdHash, webAuthnData.pubKeyX, webAuthnData.pubKeyY);
    }

    /**
     * @notice Uninstall WebAuthn validator for a kernel account.
     * @dev The kernel account need to be the `msg.sender`.
     */
    function _signerOnUninstall(bytes32 id, bytes calldata) internal override {
        if (!_isInitialized(msg.sender)) revert NotInitialized(msg.sender);
        delete webAuthnSignerStorage[id][msg.sender];
        usedIds[msg.sender]--;
    }
}
