// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {ECDSA} from "solady/utils/ECDSA.sol";
import {EIP712} from "solady/utils/EIP712.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {SignerBase} from "src/base/SignerBase.sol";
import {WeightedThresholdBase} from "src/base/WeightedThresholdBase.sol";
import {
    ERC1271_MAGICVALUE,
    ERC1271_INVALID,
    SIG_VALIDATION_FAILED_UINT,
    SIG_VALIDATION_SUCCESS_UINT,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_HOOK,
    MODULE_TYPE_SIGNER,
    MODULE_TYPE_STATELESS_VALIDATOR,
    MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER
} from "src/types/Constants.sol";
import {IModule, IStatelessValidator, IStatelessValidatorWithSender} from "src/interfaces/IERC7579Modules.sol";

struct WeightedECDSASignerStorage {
    uint24 totalWeight;
    uint24 threshold;
    address firstGuardian;
}

struct GuardianStorage {
    uint24 weight;
    address nextGuardian;
}

contract WeightedECDSASigner is
    EIP712,
    SignerBase,
    WeightedThresholdBase,
    IStatelessValidator,
    IStatelessValidatorWithSender
{
    // EIP712 typehash for the Proposal struct
    bytes32 private constant PROPOSAL_TYPEHASH =
        keccak256("Proposal(address account,bytes32 id,bytes callData,uint256 nonce,uint256 configurationEpoch)");
    bytes32 private constant USER_OP_TYPEHASH =
        keccak256("WeightedUserOperation(bytes32 userOpHash,uint256 configurationEpoch)");
    uint256 private constant REPLAYABLE_MODE_MASK = uint256(0x40) << 248;

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

    function _revertZeroWeightSigner() internal pure override {
        revert ZeroWeightSigner();
    }

    function _revertSignersNotSorted() internal pure override {
        revert SignersNotSorted();
    }

    mapping(bytes32 id => mapping(address kernel => WeightedECDSASignerStorage)) public weightedStorage;
    mapping(address guardian => mapping(bytes32 id => mapping(address kernel => GuardianStorage))) public guardian;
    /// @notice Monotonically increasing configuration version. It intentionally survives uninstall.
    mapping(bytes32 id => mapping(address kernel => uint256)) public configurationEpoch;

    event GuardianAdded(address indexed guardian, address indexed kernel, uint24 weight);
    event GuardianRemoved(address indexed guardian, address indexed kernel);

    function _domainNameAndVersion() internal pure override returns (string memory, string memory) {
        return ("WeightedECDSASigner", "0.0.3");
    }

    function _signerOninstall(bytes32 id, bytes calldata _data) internal override {
        // Prevent reinstall without uninstall (would orphan old guardians and corrupt totalWeight)
        if (_isInitialized(id, msg.sender)) revert AlreadyInitialized(msg.sender);

        configurationEpoch[id][msg.sender]++;

        (address[] memory _guardians, uint24[] memory _weights, uint24 _threshold) =
            abi.decode(_data, (address[], uint24[], uint24));
        require(_guardians.length == _weights.length, LengthMismatch());
        require(_guardians.length > 0, EmptyGuardians());
        require(_threshold > 0, ZeroThreshold());

        weightedStorage[id][msg.sender].firstGuardian = msg.sender;
        for (uint256 i = 0; i < _guardians.length; i++) {
            require(_guardians[i] != msg.sender, GuardianCannotBeSelf());
            require(_guardians[i] != address(0), ZeroAddressGuardian());
            require(_weights[i] != 0, ZeroWeight());
            require(guardian[_guardians[i]][id][msg.sender].weight == 0, GuardianAlreadyEnabled());
            guardian[_guardians[i]][id][msg.sender] =
                GuardianStorage({weight: _weights[i], nextGuardian: weightedStorage[id][msg.sender].firstGuardian});
            weightedStorage[id][msg.sender].firstGuardian = _guardians[i];
            weightedStorage[id][msg.sender].totalWeight += _weights[i];
            emit GuardianAdded(_guardians[i], msg.sender, _weights[i]);
        }
        require(_threshold <= weightedStorage[id][msg.sender].totalWeight, ThresholdExceedsTotalWeight());
        weightedStorage[id][msg.sender].threshold = _threshold;
    }

    function _signerOnUninstall(bytes32 id, bytes calldata) internal override {
        if (!_isInitialized(id, msg.sender)) revert NotInitialized(msg.sender);
        address currentGuardian = weightedStorage[id][msg.sender].firstGuardian;
        while (currentGuardian != msg.sender) {
            address nextGuardian = guardian[currentGuardian][id][msg.sender].nextGuardian;
            emit GuardianRemoved(currentGuardian, msg.sender);
            delete guardian[currentGuardian][id][msg.sender];
            currentGuardian = nextGuardian;
        }
        delete weightedStorage[id][msg.sender];
    }

    function isModuleType(uint256 moduleTypeId) external pure override(IModule, SignerBase) returns (bool) {
        return moduleTypeId == MODULE_TYPE_SIGNER || moduleTypeId == MODULE_TYPE_STATELESS_VALIDATOR
            || moduleTypeId == MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER;
    }

    function _isInitialized(bytes32 id, address smartAccount) internal view returns (bool) {
        return weightedStorage[id][smartAccount].totalWeight != 0;
    }

    /// @notice Weight lookup for the base aggregation logic (cfg == permission id).
    function _guardianWeight(bytes32 cfg, address account, address signer) internal view override returns (uint256) {
        return guardian[signer][cfg][account].weight;
    }

    function checkUserOpSignature(bytes32 id, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        override
        returns (uint256)
    {
        // Split signature scheme: first N-1 sigs cover the proposal and the last covers the
        // UserOperation hash. Both are EIP-712-bound to this configuration epoch.
        uint256 epoch = configurationEpoch[id][msg.sender];
        bool replayable = userOp.nonce & REPLAYABLE_MODE_MASK != 0;
        bytes32 proposalStructHash = keccak256(
            abi.encode(
                PROPOSAL_TYPEHASH,
                userOp.sender, // account address
                id, // id
                keccak256(userOp.callData), // calldata hash
                userOp.nonce, // nonce
                epoch
            )
        );
        bytes32 proposalHash = _hashForMode(proposalStructHash, replayable);
        bytes32 finalHash = _hashForMode(keccak256(abi.encode(USER_OP_TYPEHASH, userOpHash, epoch)), replayable);
        uint256 threshold = weightedStorage[id][msg.sender].threshold;
        return _verifyUserOp(id, msg.sender, proposalHash, finalHash, userOp.signature, threshold)
            ? SIG_VALIDATION_SUCCESS_UINT
            : SIG_VALIDATION_FAILED_UINT;
    }

    function _hashForMode(bytes32 structHash, bool replayable) internal view returns (bytes32) {
        return replayable ? _hashTypedDataSansChainId(structHash) : _hashTypedData(structHash);
    }

    /// @notice Validate an ERC-1271 signature
    /// @dev The `sender` parameter (requesting protocol) is intentionally unused.
    ///      This signer authenticates the SIGNERS (guardians), not the requesting protocol.
    ///      WARNING: Because sender is ignored, any protocol can request signature
    ///      validation. If you need to restrict which protocols can request signatures,
    ///      pair this signer with a CallerPolicy.
    function checkSignature(bytes32 id, address, bytes32 hash, bytes calldata sig)
        external
        view
        override
        returns (bytes4)
    {
        uint256 threshold = weightedStorage[id][msg.sender].threshold;
        return _verifySorted(id, msg.sender, hash, sig, threshold) ? ERC1271_MAGICVALUE : ERC1271_INVALID;
    }

    function validateSignatureWithData(bytes32 hash, bytes calldata signature, bytes calldata data)
        external
        view
        override(IStatelessValidator)
        returns (bool)
    {
        (address[] memory guardians, uint24[] memory weights, uint24 threshold) =
            abi.decode(data, (address[], uint24[], uint24));
        return _validateStatelessSignature(hash, signature, guardians, weights, threshold);
    }

    function validateSignatureWithDataWithSender(address, bytes32 hash, bytes calldata signature, bytes calldata data)
        external
        view
        override(IStatelessValidatorWithSender)
        returns (bool)
    {
        (address[] memory guardians, uint24[] memory weights, uint24 threshold) =
            abi.decode(data, (address[], uint24[], uint24));
        return _validateStatelessSignature(hash, signature, guardians, weights, threshold);
    }

    // ==================== Stateless (memory-config) validation ====================
    // The installed/storage-backed paths (checkUserOpSignature / checkSignature) delegate to
    // WeightedThresholdBase. The stateless paths below use caller-provided memory guardians, which
    // the base's storage-keyed _guardianWeight cannot serve, so they keep their own implementation.

    function _validateStatelessSignature(
        bytes32 hash,
        bytes calldata sig,
        address[] memory guardians,
        uint24[] memory weights,
        uint24 threshold
    ) internal view returns (bool) {
        if (threshold == 0 || guardians.length != weights.length) {
            return false;
        }

        uint256 sigCount = sig.length / 65;
        if (sigCount == 0) {
            return false;
        }

        uint256 totalWeight;
        address signer;
        address lastSigner = address(0);

        // Process all signatures except the last one
        for (uint256 i = 0; i < sigCount - 1; i++) {
            signer = ECDSA.tryRecoverCalldata(hash, sig[i * 65:(i + 1) * 65]);

            if (signer <= lastSigner) {
                return false;
            }
            lastSigner = signer;

            uint24 guardianWeight = _memoryGuardianWeight(signer, guardians, weights);
            // Revert if non-last signer has zero weight (prevents gas griefing)
            if (guardianWeight == 0) {
                revert ZeroWeightSigner();
            }
            totalWeight += guardianWeight;
            if (totalWeight >= threshold) {
                return true;
            }
        }

        // Process last signature
        signer = ECDSA.tryRecoverCalldata(hash, sig[sig.length - 65:]);
        if (signer <= lastSigner) {
            return false;
        }
        uint24 lastGuardianWeight = _memoryGuardianWeight(signer, guardians, weights);
        // If last signer has zero weight, return false (don't revert)
        if (lastGuardianWeight == 0) {
            return false;
        }
        totalWeight += lastGuardianWeight;
        if (totalWeight >= threshold) {
            return true;
        }

        return false;
    }

    function _memoryGuardianWeight(address signer, address[] memory guardians, uint24[] memory weights)
        internal
        pure
        returns (uint24)
    {
        for (uint256 i = 0; i < guardians.length; i++) {
            if (guardians[i] == signer) {
                return weights[i];
            }
        }
        return 0;
    }
}
