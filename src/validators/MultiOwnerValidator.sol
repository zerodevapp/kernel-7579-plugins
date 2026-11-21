// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

import {IModule, IStatelessValidator, IValidator} from "src/interfaces/IERC7579Modules.sol";
import {
    ERC1271_INVALID,
    ERC1271_MAGICVALUE,
    MODULE_TYPE_STATELESS_VALIDATOR,
    MODULE_TYPE_VALIDATOR,
    SIG_VALIDATION_FAILED_UINT,
    SIG_VALIDATION_SUCCESS_UINT
} from "src/types/Constants.sol";

/// @title MultiOwnerValidator
/// @author taek <leekt216@gmail.com>
/// @notice A root validator that gives multiple stateless signer configurations equal administrative rights.
/// @dev Each owner delegates verification to an external module implementing `IStatelessValidator`.
///      The signer module does not need to be installed on the account because its complete validation
///      configuration is stored here and supplied on every verification call.
///
///      Install data is `abi.encode(OwnerConfig[])`. Signatures are encoded as
///      `abi.encodePacked(ownerId, ownerSignature)`. The selected stateless validator defines both
///      `ownerSignature` and `validationData`.
///
///      Owner records use account-associated storage slots for ERC-7562 validation, and validation
///      reconstructs the configured data in memory. The aggregate validation data for one account is
///      capped at 4096 bytes so owner cleanup remains bounded.
///
///      `isModuleType(MODULE_TYPE_STATELESS_VALIDATOR)` is the only standardized capability signal.
///      It cannot prove that arbitrary validation data or signatures are usable. Integrations should
///      validate each owner configuration off-chain and retain a separately tested recovery authority.
contract MultiOwnerValidator is IValidator {
    uint256 public constant MAX_OWNERS = 32;
    uint256 public constant MAX_TOTAL_VALIDATION_DATA = 4096;
    uint256 internal constant MAX_VALIDATION_DATA_WORDS = MAX_TOTAL_VALIDATION_DATA / 32;

    struct OwnerConfig {
        bytes32 ownerId;
        address statelessValidator;
        bytes validationData;
    }

    struct Owner {
        address statelessValidator;
        uint16 validationDataLength;
        bytes32[MAX_VALIDATION_DATA_WORDS] validationDataWords;
    }

    // ownerId is the outer key so each inner owner record starts at
    // keccak256(abi.encode(account, keccak256(abi.encode(ownerId, slot)))). The header and
    // fixed-size data words therefore occupy account-associated slots base + [0, 128].
    mapping(bytes32 ownerId => mapping(address account => Owner)) internal _owners;

    mapping(address account => bytes32[]) internal _ownerIds;
    mapping(address account => mapping(bytes32 ownerId => uint256 indexPlusOne)) internal _ownerIndex;
    mapping(address account => uint256 length) internal _totalValidationData;

    event OwnerAdded(
        address indexed account, bytes32 indexed ownerId, address indexed statelessValidator, bytes validationData
    );
    event OwnerUpdated(
        address indexed account, bytes32 indexed ownerId, address indexed statelessValidator, bytes validationData
    );
    event OwnerRemoved(address indexed account, bytes32 indexed ownerId);

    error EmptyOwners();
    error InvalidOwnerId();
    error InvalidStatelessValidator(address validator);
    error OwnerAlreadyExists(bytes32 ownerId);
    error OwnerDoesNotExist(bytes32 ownerId);
    error MaxOwnersExceeded();
    error CannotRemoveLastOwner();
    error ValidationDataLimitExceeded(uint256 attempted, uint256 maximum);

    function onInstall(bytes calldata data) external payable override {
        require(!_isInitialized(msg.sender), AlreadyInitialized(msg.sender));

        OwnerConfig[] memory configs = abi.decode(data, (OwnerConfig[]));
        require(configs.length != 0, EmptyOwners());
        require(configs.length <= MAX_OWNERS, MaxOwnersExceeded());

        for (uint256 i; i < configs.length; ++i) {
            _addOwner(msg.sender, configs[i]);
        }
    }

    function onUninstall(bytes calldata) external payable override {
        require(_isInitialized(msg.sender), NotInitialized(msg.sender));

        bytes32[] storage ids = _ownerIds[msg.sender];
        uint256 length = ids.length;
        for (uint256 i; i < length; ++i) {
            bytes32 ownerId = ids[i];
            _clearOwner(_owners[ownerId][msg.sender]);
            delete _ownerIndex[msg.sender][ownerId];
        }
        delete _ownerIds[msg.sender];
        delete _totalValidationData[msg.sender];
    }

    /// @notice Adds an owner to the caller's validator configuration.
    /// @dev The caller is the smart account. An existing owner can authorize an account call to
    ///      this function, giving every owner the same ability to administer the owner set.
    function addOwner(OwnerConfig calldata config) external {
        require(_isInitialized(msg.sender), NotInitialized(msg.sender));
        _addOwner(msg.sender, config);
    }

    /// @notice Replaces an existing owner's validator or validation data without changing its identifier.
    function updateOwner(OwnerConfig calldata config) external {
        require(_isInitialized(msg.sender), NotInitialized(msg.sender));
        require(_ownerIndex[msg.sender][config.ownerId] != 0, OwnerDoesNotExist(config.ownerId));
        _validateOwnerConfig(config);

        Owner storage owner = _owners[config.ownerId][msg.sender];
        uint256 newTotal = _totalValidationData[msg.sender] - owner.validationDataLength + config.validationData.length;
        require(newTotal <= MAX_TOTAL_VALIDATION_DATA, ValidationDataLimitExceeded(newTotal, MAX_TOTAL_VALIDATION_DATA));

        _storeOwner(owner, config.statelessValidator, config.validationData);
        _totalValidationData[msg.sender] = newTotal;
        emit OwnerUpdated(msg.sender, config.ownerId, config.statelessValidator, config.validationData);
    }

    /// @notice Removes an owner while ensuring the validator cannot be left ownerless.
    function removeOwner(bytes32 ownerId) external {
        require(_isInitialized(msg.sender), NotInitialized(msg.sender));

        uint256 indexPlusOne = _ownerIndex[msg.sender][ownerId];
        require(indexPlusOne != 0, OwnerDoesNotExist(ownerId));
        require(_ownerIds[msg.sender].length > 1, CannotRemoveLastOwner());

        uint256 index = indexPlusOne - 1;
        bytes32[] storage ids = _ownerIds[msg.sender];
        uint256 lastIndex = ids.length - 1;
        if (index != lastIndex) {
            bytes32 movedOwnerId = ids[lastIndex];
            ids[index] = movedOwnerId;
            _ownerIndex[msg.sender][movedOwnerId] = index + 1;
        }
        ids.pop();

        Owner storage owner = _owners[ownerId][msg.sender];
        _totalValidationData[msg.sender] -= owner.validationDataLength;
        _clearOwner(owner);
        delete _ownerIndex[msg.sender][ownerId];

        emit OwnerRemoved(msg.sender, ownerId);
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        override
        returns (uint256)
    {
        if (userOp.sender != msg.sender) return SIG_VALIDATION_FAILED_UINT;
        return _verifySignature(msg.sender, userOpHash, userOp.signature)
            ? SIG_VALIDATION_SUCCESS_UINT
            : SIG_VALIDATION_FAILED_UINT;
    }

    /// @dev `sender` is the requesting protocol, not the account whose owner registry is used.
    function isValidSignatureWithSender(address, bytes32 hash, bytes calldata signature)
        external
        view
        override
        returns (bytes4)
    {
        return _verifySignature(msg.sender, hash, signature) ? ERC1271_MAGICVALUE : ERC1271_INVALID;
    }

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    function isInitialized(address account) external view returns (bool) {
        return _isInitialized(account);
    }

    function ownerCount(address account) external view returns (uint256) {
        return _ownerIds[account].length;
    }

    function ownerIdAt(address account, uint256 index) external view returns (bytes32) {
        return _ownerIds[account][index];
    }

    function owners(address account, bytes32 ownerId)
        external
        view
        returns (address statelessValidator, bytes memory validationData)
    {
        Owner storage owner = _owners[ownerId][account];
        return (owner.statelessValidator, _loadValidationData(owner));
    }

    function totalValidationData(address account) external view returns (uint256) {
        return _totalValidationData[account];
    }

    function _isInitialized(address account) internal view returns (bool) {
        return _ownerIds[account].length != 0;
    }

    function _addOwner(address account, OwnerConfig memory config) internal {
        require(_ownerIds[account].length < MAX_OWNERS, MaxOwnersExceeded());
        require(_ownerIndex[account][config.ownerId] == 0, OwnerAlreadyExists(config.ownerId));
        _validateOwnerConfig(config);

        uint256 newTotal = _totalValidationData[account] + config.validationData.length;
        require(newTotal <= MAX_TOTAL_VALIDATION_DATA, ValidationDataLimitExceeded(newTotal, MAX_TOTAL_VALIDATION_DATA));

        _storeOwner(_owners[config.ownerId][account], config.statelessValidator, config.validationData);
        _ownerIds[account].push(config.ownerId);
        _ownerIndex[account][config.ownerId] = _ownerIds[account].length;
        _totalValidationData[account] = newTotal;

        emit OwnerAdded(account, config.ownerId, config.statelessValidator, config.validationData);
    }

    function _validateOwnerConfig(OwnerConfig memory config) internal view {
        require(config.ownerId != bytes32(0), InvalidOwnerId());

        address statelessValidator = config.statelessValidator;
        require(statelessValidator.code.length != 0, InvalidStatelessValidator(statelessValidator));

        (bool success, bytes memory result) =
            statelessValidator.staticcall(abi.encodeCall(IModule.isModuleType, (MODULE_TYPE_STATELESS_VALIDATOR)));
        uint256 supported;
        if (result.length == 32) {
            assembly ("memory-safe") {
                supported := mload(add(result, 0x20))
            }
        }
        require(success && supported == 1, InvalidStatelessValidator(statelessValidator));
    }

    function _verifySignature(address account, bytes32 hash, bytes calldata signature) internal view returns (bool) {
        if (signature.length < 32) return false;

        bytes32 ownerId;
        assembly ("memory-safe") {
            ownerId := calldataload(signature.offset)
        }

        Owner storage owner = _owners[ownerId][account];
        bytes calldata ownerSignature = signature[32:];

        if (owner.statelessValidator == address(0)) return false;
        bytes memory validationData = _loadValidationData(owner);
        try IStatelessValidator(owner.statelessValidator)
            .validateSignatureWithData(hash, ownerSignature, validationData) returns (
            bool isValid
        ) {
            return isValid;
        } catch {
            return false;
        }
    }

    function _storeOwner(Owner storage owner, address statelessValidator, bytes memory validationData) internal {
        uint256 oldWordCount = _wordCount(owner.validationDataLength);
        uint256 length = validationData.length;
        uint256 newWordCount = _wordCount(length);

        owner.statelessValidator = statelessValidator;
        // Safe because every caller enforces length <= MAX_TOTAL_VALIDATION_DATA (4096).
        // forge-lint: disable-next-line(unsafe-typecast)
        owner.validationDataLength = uint16(length);

        for (uint256 i; i < newWordCount; ++i) {
            bytes32 word;
            assembly ("memory-safe") {
                word := mload(add(add(validationData, 0x20), mul(i, 0x20)))
            }

            if (i + 1 == newWordCount && length & 31 != 0) {
                uint256 validBytes = length & 31;
                word = bytes32(uint256(word) & (type(uint256).max << ((32 - validBytes) * 8)));
            }
            owner.validationDataWords[i] = word;
        }

        for (uint256 i = newWordCount; i < oldWordCount; ++i) {
            delete owner.validationDataWords[i];
        }
    }

    function _loadValidationData(Owner storage owner) internal view returns (bytes memory validationData) {
        uint256 length = owner.validationDataLength;
        validationData = new bytes(length);

        uint256 wordCount = _wordCount(length);
        for (uint256 i; i < wordCount; ++i) {
            bytes32 word = owner.validationDataWords[i];
            assembly ("memory-safe") {
                mstore(add(add(validationData, 0x20), mul(i, 0x20)), word)
            }
        }
    }

    function _clearOwner(Owner storage owner) internal {
        uint256 wordCount = _wordCount(owner.validationDataLength);
        for (uint256 i; i < wordCount; ++i) {
            delete owner.validationDataWords[i];
        }
        delete owner.statelessValidator;
        delete owner.validationDataLength;
    }

    function _wordCount(uint256 length) internal pure returns (uint256) {
        return (length + 31) >> 5;
    }
}
