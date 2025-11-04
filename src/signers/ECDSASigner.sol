pragma solidity ^0.8.0;

import {ECDSA} from "solady/utils/ECDSA.sol";
import {ISigner, IStatelessValidator, IStatelessValidatorWithSender} from "src/interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {
    SIG_VALIDATION_SUCCESS_UINT,
    SIG_VALIDATION_FAILED_UINT,
    MODULE_TYPE_SIGNER,
    MODULE_TYPE_STATELESS_VALIDATOR,
    MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER,
    ERC1271_MAGICVALUE,
    ERC1271_INVALID
} from "src/types/Constants.sol";

contract ECDSASigner is SignerBase, IStatelessValidator, IStatelessValidatorWithSender {
    mapping(address => uint256) public usedIds;
    mapping(bytes32 id => mapping(address wallet => address)) public signer;

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_SIGNER || typeID == MODULE_TYPE_STATELESS_VALIDATOR
            || typeID == MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER;
    }

    function isInitialized(address wallet) external view override returns (bool) {
        return usedIds[wallet] > 0;
    }

    function _verifySignature(bytes32 hash, bytes calldata sig, address _signer) internal view returns (bool) {
        if (_signer == ECDSA.tryRecoverCalldata(hash, sig)) {
            return true;
        }
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(hash);
        address recovered = ECDSA.tryRecoverCalldata(ethHash, sig);
        return _signer == recovered;
    }

    function checkUserOpSignature(bytes32 id, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        override
        returns (uint256)
    {
        address owner = signer[id][msg.sender];
        return
            _verifySignature(userOpHash, userOp.signature, owner)
                ? SIG_VALIDATION_SUCCESS_UINT
                : SIG_VALIDATION_FAILED_UINT;
    }

    function checkSignature(bytes32 id, address sender, bytes32 hash, bytes calldata sig)
        external
        view
        override
        returns (bytes4)
    {
        address owner = signer[id][msg.sender];
        return _verifySignature(hash, sig, owner) ? ERC1271_MAGICVALUE : ERC1271_INVALID;
    }

    function _signerOninstall(bytes32 id, bytes calldata _data) internal {
        require(signer[id][msg.sender] == address(0));
        usedIds[msg.sender]++;
        signer[id][msg.sender] = address(bytes20(_data[0:20]));
    }

    function _signerOnUninstall(bytes32 id, bytes calldata) internal {
        require(signer[id][msg.sender] != address(0));
        delete signer[id][msg.sender];
        usedIds[msg.sender]--;
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
}
