pragma solidity ^0.8.0;

import {ECDSA} from "solady/utils/ECDSA.sol";
import {IModule, ISigner, IStatelessValidator, IStatelessValidatorWithSender} from "src/interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {SignerBase} from "src/base/SignerBase.sol";
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
    error InvalidDataLength();
    error ZeroAddressSigner();

    mapping(bytes32 id => mapping(address wallet => address)) public signer;

    function isModuleType(uint256 typeID) external pure override(IModule, SignerBase) returns (bool) {
        return typeID == MODULE_TYPE_SIGNER || typeID == MODULE_TYPE_STATELESS_VALIDATOR
            || typeID == MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER;
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
        // Fail if signer is not installed (prevents matching with failed recovery)
        if (owner == address(0)) return SIG_VALIDATION_FAILED_UINT;
        return _verifySignature(userOpHash, userOp.signature, owner)
            ? SIG_VALIDATION_SUCCESS_UINT
            : SIG_VALIDATION_FAILED_UINT;
    }

    /// @notice Validate an ERC-1271 signature
    /// @dev The `sender` parameter (requesting protocol) is intentionally unused.
    ///      This signer authenticates the SIGNER (owner), not the requesting protocol.
    ///      WARNING: Because sender is ignored, any protocol can request signature
    ///      validation. If you need to restrict which protocols can request signatures,
    ///      pair this signer with a CallerPolicy.
    function checkSignature(bytes32 id, address sender, bytes32 hash, bytes calldata sig)
        external
        view
        override
        returns (bytes4)
    {
        address owner = signer[id][msg.sender];
        // Fail if signer is not installed (prevents matching with failed recovery)
        if (owner == address(0)) return ERC1271_INVALID;
        return _verifySignature(hash, sig, owner) ? ERC1271_MAGICVALUE : ERC1271_INVALID;
    }

    function _signerOninstall(bytes32 id, bytes calldata _data) internal override {
        require(signer[id][msg.sender] == address(0), "Already installed");
        if (_data.length != 20) revert InvalidDataLength();
        address signerAddr = address(bytes20(_data[0:20]));
        if (signerAddr == address(0)) revert ZeroAddressSigner();
        signer[id][msg.sender] = signerAddr;
    }

    function _signerOnUninstall(bytes32 id, bytes calldata) internal override {
        require(signer[id][msg.sender] != address(0));
        delete signer[id][msg.sender];
    }

    function validateSignatureWithData(bytes32 hash, bytes calldata signature, bytes calldata data)
        external
        view
        override(IStatelessValidator)
        returns (bool)
    {
        return _verifySignature(hash, signature, address(bytes20(data[0:20])));
    }

    function validateSignatureWithDataWithSender(address, bytes32 hash, bytes calldata signature, bytes calldata data)
        external
        view
        override(IStatelessValidatorWithSender)
        returns (bool)
    {
        return _verifySignature(hash, signature, address(bytes20(data[0:20])));
    }
}
