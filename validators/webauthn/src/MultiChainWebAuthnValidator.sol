// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {IValidator, IHook} from "kernel/interfaces/IERC7579Modules.sol";
import {MODULE_TYPE_VALIDATOR, MODULE_TYPE_HOOK} from "kernel/types/Constants.sol";
import {PackedUserOperation} from "kernel/interfaces/PackedUserOperation.sol";
import {
    SIG_VALIDATION_FAILED_UINT,
    SIG_VALIDATION_SUCCESS_UINT,
    ERC1271_MAGICVALUE,
    ERC1271_INVALID
} from "kernel/types/Constants.sol";
import {WebAuthn} from "./WebAuthn.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {MerkleProofLib} from "solady/utils/MerkleProofLib.sol";

struct WebAuthnValidatorData {
    uint256 pubKeyX;
    uint256 pubKeyY;
}

bytes constant DUMMY_WEBAUTHN_SIG = hex"00000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000001635bc6d0f68ff895cae8a288ecf7542a6a9cd555df784b73e1e2ea7e9104b1db15e9015d280cb19527881c625fee43fd3a405d5b0d199a8c8e6589a7381209e40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002549960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000867b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22746278584e465339585f3442797231634d77714b724947422d5f3330613051685a36793775634d30424f45222c226f726967696e223a22687474703a2f2f6c6f63616c686f73743a33303030222c2263726f73734f726967696e223a66616c73657d0000000000000000000000000000000000000000000000000000";

contract MultiChainWebAuthnValidator is IValidator {
    // The location of the challenge in the clientDataJSON
    uint256 constant CHALLENGE_LOCATION = 23;

    // Emitted when a bad key is provided.
    error InvalidPublicKey();

    // Emitted when the public key of a kernel is changed.
    event WebAuthnPublicKeyRegistered(
        address indexed kernel, bytes32 indexed authenticatorIdHash, uint256 pubKeyX, uint256 pubKeyY
    );
    event OwnerRegistered(address indexed kernel, address indexed owner);

    // The P256 public keys of a kernel.
    mapping(address kernel => WebAuthnValidatorData WebAuthnValidatorData) public webAuthnValidatorStorage;

    function onInstall(bytes calldata _data) external payable override {
        // check if the webauthn validator is already initialized
        if (_isInitialized(msg.sender)) revert AlreadyInitialized(msg.sender);
        // check validity of the public key
        (WebAuthnValidatorData memory webAuthnData, bytes32 authenticatorIdHash) =
            abi.decode(_data, (WebAuthnValidatorData, bytes32));
        if (webAuthnData.pubKeyX == 0 || webAuthnData.pubKeyY == 0) {
            revert InvalidPublicKey();
        }
        // Update the key (so a sstore)
        webAuthnValidatorStorage[msg.sender] = webAuthnData;
        // And emit the event
        emit WebAuthnPublicKeyRegistered(msg.sender, authenticatorIdHash, webAuthnData.pubKeyX, webAuthnData.pubKeyY);
    }

    function onUninstall(bytes calldata) external payable override {
        if (!_isInitialized(msg.sender)) revert NotInitialized(msg.sender);
        delete webAuthnValidatorStorage[msg.sender];
    }

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_VALIDATOR;
    }

    function isInitialized(address smartAccount) external view override returns (bool) {
        return _isInitialized(smartAccount);
    }

    function _isInitialized(address smartAccount) internal view returns (bool) {
        return webAuthnValidatorStorage[smartAccount].pubKeyX != 0;
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
    external
    payable
    override
    returns (uint256)
    {
        (bytes calldata merkleData, bytes calldata signature) = _parseSig(userOp.signature);
        if(merkleData.length == 0) {
            return _verifySignature(msg.sender, userOpHash, signature);
        }
        bytes32 merkleRoot = bytes32(merkleData[0:32]);
        if (keccak256(signature) == keccak256(DUMMY_WEBAUTHN_SIG)) {
            (bytes32 dummyUserOpHash, bytes32[] memory proof) = abi.decode(merkleData[32:], (bytes32, bytes32[]));
            require(MerkleProofLib.verify(proof, merkleRoot, dummyUserOpHash), "hash is not in proof");
        } else {
            bytes32[] memory proof = abi.decode(merkleData[32:], (bytes32[]));
            require(MerkleProofLib.verify(proof, merkleRoot, userOpHash), "hash is not in proof");
        }
        // simple webauthn verification
        bytes32 ethRoot = ECDSA.toEthSignedMessageHash(merkleRoot);
        return _verifySignature(msg.sender, ethRoot, signature);
    }

    function isValidSignatureWithSender(address, bytes32 hash, bytes calldata sig)
    external
    view
    override
    returns (bytes4)
    {
        (bytes calldata merkleData, bytes calldata signature) = _parseSig(sig);
        if(merkleData.length == 0) {
            return _verifySignature(msg.sender, hash, signature) == SIG_VALIDATION_SUCCESS_UINT
            ? ERC1271_MAGICVALUE
            : ERC1271_INVALID;
        }
        bytes32 merkleRoot = bytes32(merkleData[0:32]);
        bytes32[] memory proof = abi.decode(merkleData[32:], (bytes32[]));
        require(MerkleProofLib.verify(proof, merkleRoot, hash), "hash is not in proof");
        // simple ecdsa verification
        bytes32 ethRoot = ECDSA.toEthSignedMessageHash(merkleRoot);
        return _verifySignature(msg.sender, ethRoot, signature) == SIG_VALIDATION_SUCCESS_UINT
            ? ERC1271_MAGICVALUE
            : ERC1271_INVALID;

    }

    /**
     * @notice Verify a signature.
     */
    function _verifySignature(address account, bytes32 hash, bytes calldata signature) private view returns (uint256) {
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
        WebAuthnValidatorData memory webAuthnData = webAuthnValidatorStorage[account];

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
            return SIG_VALIDATION_SUCCESS_UINT;
        }

        return SIG_VALIDATION_FAILED_UINT;
    }

    function _parseSig(bytes calldata rawSig) internal pure returns(bytes calldata merkleData, bytes calldata signature) {
        assembly {
            merkleData.offset := add(add(rawSig.offset, 32), calldataload(rawSig.offset))
            merkleData.length := calldataload(sub(merkleData.offset, 32))
            signature.offset := add(add(rawSig.offset, 32), calldataload(add(rawSig.offset, 32)))
            signature.length := calldataload(sub(signature.offset, 32))
        }
    }
}
