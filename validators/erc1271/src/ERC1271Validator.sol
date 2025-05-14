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

interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4);
}

contract ERC1271Validator is IValidator {
    mapping(address account => address verifier) public verifier;

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

        try IERC1271(_verifier).isValidSignature(hash, signature) returns(bytes4 result) {
            return result == ERC1271_MAGICVALUE ? SIG_VALIDATION_SUCCESS_UINT : SIG_VALIDATION_FAILED_UINT;
        } catch {
            return SIG_VALIDATION_FAILED_UINT;
        }

    }
}
