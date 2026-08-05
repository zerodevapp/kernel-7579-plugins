// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IValidator, IStatelessValidator, IStatelessValidatorWithSender} from "src/interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_STATELESS_VALIDATOR,
    MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER,
    SIG_VALIDATION_SUCCESS_UINT,
    SIG_VALIDATION_FAILED_UINT,
    ERC1271_MAGICVALUE,
    ERC1271_INVALID
} from "src/types/Constants.sol";
import {P256Validation} from "src/utils/P256Validation.sol";

struct P256ValidatorData {
    uint256 pubKeyX;
    uint256 pubKeyY;
}

/// @title P256Validator
/// @author taek <leekt216@gmail.com>
/// @notice ERC-7579 validator for raw P-256 signatures, including stateless dispatch.
/// @dev Requires the RIP-7212 / EIP-7951 precompile at address 0x100.
contract P256Validator is IValidator, IStatelessValidator, IStatelessValidatorWithSender {
    error InvalidDataLength();
    error InvalidPublicKey();
    error P256PrecompileNotAvailable();

    event PublicKeyRegistered(address indexed account, uint256 x, uint256 y);
    event PublicKeyRemoved(address indexed account);

    mapping(address account => P256ValidatorData) public p256ValidatorStorage;

    constructor() {
        if (!P256Validation.isPrecompileAvailable()) revert P256PrecompileNotAvailable();
    }

    function onInstall(bytes calldata data) external payable override {
        if (_isInitialized(msg.sender)) revert AlreadyInitialized(msg.sender);
        if (data.length != 64) revert InvalidDataLength();

        (uint256 x, uint256 y) = abi.decode(data, (uint256, uint256));
        if (!P256Validation.isValidPublicKey(x, y)) revert InvalidPublicKey();

        p256ValidatorStorage[msg.sender] = P256ValidatorData(x, y);
        emit PublicKeyRegistered(msg.sender, x, y);
    }

    function onUninstall(bytes calldata) external payable override {
        if (!_isInitialized(msg.sender)) revert NotInitialized(msg.sender);
        delete p256ValidatorStorage[msg.sender];
        emit PublicKeyRemoved(msg.sender);
    }

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_VALIDATOR || typeID == MODULE_TYPE_STATELESS_VALIDATOR
            || typeID == MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER;
    }

    function isInitialized(address account) external view returns (bool) {
        return _isInitialized(account);
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        override
        returns (uint256)
    {
        P256ValidatorData storage key = p256ValidatorStorage[msg.sender];
        return P256Validation.verify(userOpHash, userOp.signature, key.pubKeyX, key.pubKeyY)
            ? SIG_VALIDATION_SUCCESS_UINT
            : SIG_VALIDATION_FAILED_UINT;
    }

    function isValidSignatureWithSender(address, bytes32 hash, bytes calldata signature)
        external
        view
        override
        returns (bytes4)
    {
        P256ValidatorData storage key = p256ValidatorStorage[msg.sender];
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

    function _isInitialized(address account) internal view returns (bool) {
        P256ValidatorData storage key = p256ValidatorStorage[account];
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
