// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IModule, IStatelessValidator, IStatelessValidatorWithSender} from "src/interfaces/IERC7579Modules.sol";
import {SignerBase} from "src/base/SignerBase.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {
    MODULE_TYPE_SIGNER,
    MODULE_TYPE_STATELESS_VALIDATOR,
    MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER,
    SIG_VALIDATION_SUCCESS_UINT,
    SIG_VALIDATION_FAILED_UINT,
    ERC1271_MAGICVALUE,
    ERC1271_INVALID
} from "src/types/Constants.sol";
import {P256Validation} from "src/utils/P256Validation.sol";

struct P256SignerData {
    uint256 pubKeyX;
    uint256 pubKeyY;
}

/// @title P256Signer
/// @author taek <leekt216@gmail.com>
/// @notice Permission signer for raw P-256 signatures, including stateless dispatch.
/// @dev Requires the RIP-7212 / EIP-7951 precompile at address 0x100.
contract P256Signer is SignerBase, IStatelessValidator, IStatelessValidatorWithSender {
    error InvalidDataLength();
    error InvalidPublicKey();
    error P256PrecompileNotAvailable();

    event PublicKeyRegistered(address indexed account, bytes32 indexed id, uint256 x, uint256 y);
    event PublicKeyRemoved(address indexed account, bytes32 indexed id);

    mapping(bytes32 id => mapping(address account => P256SignerData)) public p256SignerStorage;

    constructor() {
        if (!P256Validation.isPrecompileAvailable()) revert P256PrecompileNotAvailable();
    }

    function isModuleType(uint256 typeID) external pure override(IModule, SignerBase) returns (bool) {
        return typeID == MODULE_TYPE_SIGNER || typeID == MODULE_TYPE_STATELESS_VALIDATOR
            || typeID == MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER;
    }

    function isInitialized(bytes32 id, address account) external view returns (bool) {
        return _isInitialized(id, account);
    }

    function checkUserOpSignature(bytes32 id, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        override
        returns (uint256)
    {
        P256SignerData storage key = p256SignerStorage[id][msg.sender];
        return P256Validation.verify(userOpHash, userOp.signature, key.pubKeyX, key.pubKeyY)
            ? SIG_VALIDATION_SUCCESS_UINT
            : SIG_VALIDATION_FAILED_UINT;
    }

    function checkSignature(bytes32 id, address, bytes32 hash, bytes calldata signature)
        external
        view
        override
        returns (bytes4)
    {
        P256SignerData storage key = p256SignerStorage[id][msg.sender];
        return P256Validation.verify(hash, signature, key.pubKeyX, key.pubKeyY) ? ERC1271_MAGICVALUE : ERC1271_INVALID;
    }

    function validateSignatureWithData(bytes32 hash, bytes calldata signature, bytes calldata data)
        external
        view
        override
        returns (bool)
    {
        return _validateStateless(hash, signature, data);
    }

    function validateSignatureWithDataWithSender(address, bytes32 hash, bytes calldata signature, bytes calldata data)
        external
        view
        override
        returns (bool)
    {
        return _validateStateless(hash, signature, data);
    }

    function _signerOninstall(bytes32 id, bytes calldata data) internal override {
        if (_isInitialized(id, msg.sender)) revert AlreadyInitialized(msg.sender);
        if (data.length != 64) revert InvalidDataLength();

        (uint256 x, uint256 y) = abi.decode(data, (uint256, uint256));
        if (!P256Validation.isValidPublicKey(x, y)) revert InvalidPublicKey();

        p256SignerStorage[id][msg.sender] = P256SignerData(x, y);
        emit PublicKeyRegistered(msg.sender, id, x, y);
    }

    function _signerOnUninstall(bytes32 id, bytes calldata) internal override {
        if (!_isInitialized(id, msg.sender)) revert NotInitialized(msg.sender);
        delete p256SignerStorage[id][msg.sender];
        emit PublicKeyRemoved(msg.sender, id);
    }

    function _isInitialized(bytes32 id, address account) internal view returns (bool) {
        P256SignerData storage key = p256SignerStorage[id][account];
        return key.pubKeyX != 0 || key.pubKeyY != 0;
    }

    function _validateStateless(bytes32 hash, bytes calldata signature, bytes calldata data)
        internal
        view
        returns (bool)
    {
        (uint256 x, uint256 y, bool validKey) = P256Validation.decodePublicKey(data);
        return validKey && P256Validation.verify(hash, signature, x, y);
    }
}
