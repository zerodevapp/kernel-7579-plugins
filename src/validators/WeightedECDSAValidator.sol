// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {ECDSA} from "solady/utils/ECDSA.sol";
import {EIP712} from "solady/utils/EIP712.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IValidator, IModule} from "src/interfaces/IERC7579Modules.sol";
import {WeightedThresholdBase} from "src/base/WeightedThresholdBase.sol";
import {
    ERC1271_MAGICVALUE,
    ERC1271_INVALID,
    SIG_VALIDATION_FAILED_UINT,
    SIG_VALIDATION_SUCCESS_UINT,
    MODULE_TYPE_VALIDATOR
} from "src/types/Constants.sol";

struct WeightedECDSAValidatorStorage {
    uint24 totalWeight;
    uint24 threshold;
    address firstGuardian;
}

struct GuardianStorage {
    uint24 weight;
    address nextGuardian;
}

/// @title WeightedECDSAValidator
/// @author taek <leekt216@gmail.com>
/// @notice Weighted guardian-multisig validator. A thin adapter over WeightedThresholdBase: it owns
///         a single-config guardian set per account and delegates all signature aggregation to the
///         shared base, adopting the (EC-01-fixed) split-signature scheme.
/// @dev    This variant targets EntryPoint v0.7 (the last UserOp signature is over the eth-signed
///         userOpHash). New v4 / EntryPoint v0.9 accounts should use WeightedECDSAValidatorV09,
///         which overrides only `_finalUserOpHash`.
contract WeightedECDSAValidator is EIP712, WeightedThresholdBase, IValidator {
    /// @dev EIP712 typehash for the Proposal struct (id fixed to bytes32(0): one config per account).
    bytes32 private constant PROPOSAL_TYPEHASH =
        keccak256("Proposal(address account,bytes32 id,bytes callData,uint256 nonce)");

    error ZeroWeightSigner();
    error SignersNotSorted();
    error LengthMismatch();
    error EmptyGuardians();
    error ZeroThreshold();
    error GuardianCannotBeSelf();
    error ZeroAddressGuardian();
    error ZeroWeight();
    error GuardianAlreadyEnabled();
    error ThresholdExceedsTotalWeight();

    mapping(address kernel => WeightedECDSAValidatorStorage) public weightedStorage;
    mapping(address guardian => mapping(address kernel => GuardianStorage)) public guardian;

    event GuardianAdded(address indexed guardian, address indexed kernel, uint24 weight);
    event GuardianRemoved(address indexed guardian, address indexed kernel);

    function _domainNameAndVersion() internal pure override returns (string memory, string memory) {
        return ("WeightedECDSAValidator", "0.0.4");
    }

    function _revertZeroWeightSigner() internal pure override {
        revert ZeroWeightSigner();
    }

    function _revertSignersNotSorted() internal pure override {
        revert SignersNotSorted();
    }

    /// @notice Single-config weight lookup for the base aggregation (cfg is ignored).
    function _guardianWeight(bytes32, address account, address signer) internal view override returns (uint256) {
        return guardian[signer][account].weight;
    }

    /// @notice Hash the LAST UserOp signature must sign. ep v0.7 uses the eth-signed userOpHash.
    /// @dev Overridden by WeightedECDSAValidatorV09 to return the raw userOpHash (ep v0.9).
    function _finalUserOpHash(bytes32 userOpHash) internal view virtual returns (bytes32) {
        return ECDSA.toEthSignedMessageHash(userOpHash);
    }

    // ==================== install / uninstall ====================

    function onInstall(bytes calldata _data) external payable override {
        if (_isInitialized(msg.sender)) revert AlreadyInitialized(msg.sender);

        (address[] memory _guardians, uint24[] memory _weights, uint24 _threshold) =
            abi.decode(_data, (address[], uint24[], uint24));
        require(_guardians.length == _weights.length, LengthMismatch());
        require(_guardians.length > 0, EmptyGuardians());
        require(_threshold > 0, ZeroThreshold());

        // Sentinel: firstGuardian starts as the account itself and terminates the linked list.
        // No install-time sort is required; de-dup is enforced via GuardianAlreadyEnabled.
        weightedStorage[msg.sender].firstGuardian = msg.sender;
        for (uint256 i = 0; i < _guardians.length; i++) {
            require(_guardians[i] != msg.sender, GuardianCannotBeSelf());
            require(_guardians[i] != address(0), ZeroAddressGuardian());
            require(_weights[i] != 0, ZeroWeight());
            require(guardian[_guardians[i]][msg.sender].weight == 0, GuardianAlreadyEnabled());
            guardian[_guardians[i]][msg.sender] =
                GuardianStorage({weight: _weights[i], nextGuardian: weightedStorage[msg.sender].firstGuardian});
            weightedStorage[msg.sender].firstGuardian = _guardians[i];
            weightedStorage[msg.sender].totalWeight += _weights[i];
            emit GuardianAdded(_guardians[i], msg.sender, _weights[i]);
        }
        require(_threshold <= weightedStorage[msg.sender].totalWeight, ThresholdExceedsTotalWeight());
        weightedStorage[msg.sender].threshold = _threshold;
    }

    function onUninstall(bytes calldata) external payable override {
        if (!_isInitialized(msg.sender)) revert NotInitialized(msg.sender);
        address currentGuardian = weightedStorage[msg.sender].firstGuardian;
        while (currentGuardian != msg.sender) {
            address nextGuardian = guardian[currentGuardian][msg.sender].nextGuardian;
            emit GuardianRemoved(currentGuardian, msg.sender);
            delete guardian[currentGuardian][msg.sender];
            currentGuardian = nextGuardian;
        }
        delete weightedStorage[msg.sender];
    }

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    function isInitialized(address smartAccount) external view returns (bool) {
        return _isInitialized(smartAccount);
    }

    function _isInitialized(address smartAccount) internal view returns (bool) {
        return weightedStorage[smartAccount].totalWeight != 0;
    }

    // ==================== validation ====================

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        override
        returns (uint256)
    {
        uint256 threshold = weightedStorage[msg.sender].threshold;
        // Split signature scheme: first N-1 sigs over the EIP712 proposalHash (id = 0), last sig
        // over the ep-specific final userOp hash. See WeightedThresholdBase._verifyUserOp.
        bytes32 proposalHash = _hashTypedData(
            keccak256(
                abi.encode(PROPOSAL_TYPEHASH, userOp.sender, bytes32(0), keccak256(userOp.callData), userOp.nonce)
            )
        );
        bytes32 finalHash = _finalUserOpHash(userOpHash);
        return _verifyUserOp(bytes32(0), msg.sender, proposalHash, finalHash, userOp.signature, threshold)
            ? SIG_VALIDATION_SUCCESS_UINT
            : SIG_VALIDATION_FAILED_UINT;
    }

    /// @notice ERC-1271 validation. ep-agnostic and byte-identical across variants (signs `hash`
    ///         directly). This is the EC-01-critical path: strictly ascending signers, ordering
    ///         check before weight is counted.
    function isValidSignatureWithSender(address, bytes32 hash, bytes calldata data) external view returns (bytes4) {
        uint256 threshold = weightedStorage[msg.sender].threshold;
        return _verifySorted(bytes32(0), msg.sender, hash, data, threshold) ? ERC1271_MAGICVALUE : ERC1271_INVALID;
    }
}

/// @title WeightedECDSAValidatorV09
/// @author taek <leekt216@gmail.com>
/// @notice WeightedECDSAValidator variant for new v4 / EntryPoint v0.9 accounts. The last UserOp
///         signature signs the RAW userOpHash (no eth-signed prefix); everything else is inherited.
contract WeightedECDSAValidatorV09 is WeightedECDSAValidator {
    /// @inheritdoc WeightedECDSAValidator
    function _finalUserOpHash(bytes32 userOpHash) internal view override returns (bytes32) {
        return userOpHash; // ep v0.9: sign the raw userOpHash
    }
}
