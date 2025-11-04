// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {ECDSA} from "solady/utils/ECDSA.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {
    IValidator,
    IHook,
    IStatelessValidator,
    IStatelessValidatorWithSender
} from "src/interfaces/IERC7579Modules.sol";
import {
    SIG_VALIDATION_SUCCESS_UINT,
    SIG_VALIDATION_FAILED_UINT,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_HOOK,
    MODULE_TYPE_STATELESS_VALIDATOR,
    MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER,
    ERC1271_MAGICVALUE,
    ERC1271_INVALID
} from "src/types/Constants.sol";

struct ECDSAValidatorStorage {
    address owner;
}

contract ECDSAValidator is IValidator, IHook, IStatelessValidator, IStatelessValidatorWithSender {
    event OwnerRegistered(address indexed kernel, address indexed owner);

    mapping(address => ECDSAValidatorStorage) public ecdsaValidatorStorage;

    function onInstall(bytes calldata _data) external payable override {
        if (_isInitialized(msg.sender)) revert AlreadyInitialized(msg.sender);
        address owner = address(bytes20(_data[0:20]));
        ecdsaValidatorStorage[msg.sender].owner = owner;
        emit OwnerRegistered(msg.sender, owner);
    }

    function onUninstall(bytes calldata) external payable override {
        if (!_isInitialized(msg.sender)) revert NotInitialized(msg.sender);
        delete ecdsaValidatorStorage[msg.sender];
    }

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_VALIDATOR || typeID == MODULE_TYPE_HOOK
            || typeID == MODULE_TYPE_STATELESS_VALIDATOR || typeID == MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER;
    }

    function isInitialized(address smartAccount) external view override returns (bool) {
        return _isInitialized(smartAccount);
    }

    function _isInitialized(address smartAccount) internal view returns (bool) {
        return ecdsaValidatorStorage[smartAccount].owner != address(0);
    }

    function _verifySignature(bytes32 hash, bytes calldata sig, address signer) internal view returns (bool) {
        if (signer == ECDSA.tryRecoverCalldata(hash, sig)) {
            return true;
        }
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(hash);
        address recovered = ECDSA.tryRecoverCalldata(ethHash, sig);
        return signer == recovered;
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        override
        returns (uint256)
    {
        address owner = ecdsaValidatorStorage[msg.sender].owner;
        return
            _verifySignature(userOpHash, userOp.signature, owner)
                ? SIG_VALIDATION_SUCCESS_UINT
                : SIG_VALIDATION_FAILED_UINT;
    }

    function isValidSignatureWithSender(address, bytes32 hash, bytes calldata sig)
        external
        view
        override
        returns (bytes4)
    {
        address owner = ecdsaValidatorStorage[msg.sender].owner;
        return _verifySignature(hash, sig, owner) ? ERC1271_MAGICVALUE : ERC1271_INVALID;
    }

    function validateSignatureWithData(bytes32 hash, bytes calldata signature, bytes calldata data)
        external
        view
        returns (bool)
    {
        return _verifySignature(hash, signature, address(bytes20(data[0:20])));
    }

    function validateSignatureWithDataWithSender(address, bytes32 hash, bytes calldata signature, bytes calldata data)
        external
        view
        returns (bool)
    {
        return _verifySignature(hash, signature, address(bytes20(data[0:20])));
    }

    function preCheck(address msgSender, uint256, bytes calldata) external payable override returns (bytes memory) {
        require(msgSender == ecdsaValidatorStorage[msg.sender].owner, "ECDSAValidator: sender is not owner");
        return hex"";
    }

    function postCheck(bytes calldata hookData) external payable override {}
}
