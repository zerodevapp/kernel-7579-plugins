pragma solidity ^0.8.0;

import {IValidator, IHook} from "kernel/src/interfaces/IERC7579Modules.sol";
import {MODULE_TYPE_VALIDATOR, MODULE_TYPE_HOOK} from "kernel/src/types/Constants.sol";
import {PackedUserOperation} from "kernel/src/interfaces/PackedUserOperation.sol";
import {
    SIG_VALIDATION_FAILED_UINT,
    SIG_VALIDATION_SUCCESS_UINT,
    ERC1271_MAGICVALUE,
    ERC1271_INVALID
} from "kernel/src/types/Constants.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {EIP712} from "solady/utils/EIP712.sol";

interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4);
}

// keccak256("MessageHash(bytes32 hash)")
bytes32 constant MESSAGE_TYPE_HASH = 0xddbb42c14c926ce2b204d00ecc48d770e111c85fe954c1bbbb4a7f6f4b2fbbb9;

contract ERC1271Validator is IValidator, EIP712 {
    mapping(address account => address verifier) public verifier;

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "ERC1271Validator";
        version = "0.0.1";
    }

    function onInstall(bytes calldata _data) external payable override {
        verifier[msg.sender] = address(bytes20(_data[0:20]));
    }

    function onUninstall(bytes calldata) external payable override {
        delete verifier[msg.sender];
    }

    function isModuleType(uint256 typeID) external view override returns (bool) {
        return typeID == MODULE_TYPE_VALIDATOR;
    }

    function isInitialized(address smartAccount) external view override returns (bool) {
        return _isInitialized(smartAccount);
    }

    function _isInitialized(address smartAccount) internal view returns (bool) {
        return verifier[smartAccount] != address(0);
    }

    function validateUserOp(PackedUserOperation calldata _userOp, bytes32 _userOpHash)
        external
        payable
        override
        returns (uint256)
    {
        return _verifySignature(msg.sender, _userOpHash, _userOp.signature);
    }

    function isValidSignatureWithSender(address sender, bytes32 hash, bytes calldata data)
        external
        view
        returns (bytes4)
    {
        return _verifySignature(msg.sender, hash, data) == SIG_VALIDATION_SUCCESS_UINT
            ? ERC1271_MAGICVALUE
            : ERC1271_INVALID;
    }

    function _verifySignature(address account, bytes32 hash, bytes calldata signature) private view returns (uint256) {
        address _verifier = verifier[account];

        bytes32 wrappedHash = _toMessageTypedDataHash(hash);
        try IERC1271(_verifier).isValidSignature(wrappedHash, signature) returns (bytes4 result) {
            return result == ERC1271_MAGICVALUE ? SIG_VALIDATION_SUCCESS_UINT : SIG_VALIDATION_FAILED_UINT;
        } catch {
            return SIG_VALIDATION_FAILED_UINT;
        }
    }

    function _toMessageTypedDataHash(bytes32 hash) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(MESSAGE_TYPE_HASH, hash));
        return _hashTypedData(structHash);
    }
}
