// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {ECDSA} from "solady/utils/ECDSA.sol";
import {EIP712} from "solady/utils/EIP712.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {SignerBase} from "src/base/SignerBase.sol";
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

contract WeightedECDSASigner is EIP712, SignerBase, IStatelessValidator, IStatelessValidatorWithSender {
    // EIP712 typehash for the Proposal struct
    bytes32 private constant PROPOSAL_TYPEHASH =
        keccak256("Proposal(address account,bytes32 id,bytes callData,uint256 nonce)");

    error ZeroWeightSigner();

    mapping(bytes32 id => mapping(address kernel => WeightedECDSASignerStorage)) public weightedStorage;
    mapping(address guardian => mapping(bytes32 id => mapping(address kernel => GuardianStorage))) public guardian;

    event GuardianAdded(address indexed guardian, address indexed kernel, uint24 weight);
    event GuardianRemoved(address indexed guardian, address indexed kernel);

    function _domainNameAndVersion() internal pure override returns (string memory, string memory) {
        return ("WeightedECDSASigner", "0.0.2");
    }

    function _signerOninstall(bytes32 id, bytes calldata _data) internal override {
        // Prevent reinstall without uninstall (would orphan old guardians and corrupt totalWeight)
        if (_isInitialized(id, msg.sender)) revert AlreadyInitialized(msg.sender);

        (address[] memory _guardians, uint24[] memory _weights, uint24 _threshold) =
            abi.decode(_data, (address[], uint24[], uint24));
        require(_guardians.length == _weights.length, "Length mismatch");
        require(_guardians.length > 0, "No guardians");
        require(_threshold > 0, "Zero threshold");

        weightedStorage[id][msg.sender].firstGuardian = msg.sender;
        for (uint256 i = 0; i < _guardians.length; i++) {
            require(_guardians[i] != msg.sender, "Guardian cannot be self");
            require(_guardians[i] != address(0), "Guardian cannot be 0");
            require(_weights[i] != 0, "Weight cannot be 0");
            require(guardian[_guardians[i]][id][msg.sender].weight == 0, "Guardian already enabled");
            guardian[_guardians[i]][id][msg.sender] =
                GuardianStorage({weight: _weights[i], nextGuardian: weightedStorage[id][msg.sender].firstGuardian});
            weightedStorage[id][msg.sender].firstGuardian = _guardians[i];
            weightedStorage[id][msg.sender].totalWeight += _weights[i];
            emit GuardianAdded(_guardians[i], msg.sender, _weights[i]);
        }
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

    function checkUserOpSignature(bytes32 id, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        override
        returns (uint256)
    {
        return _validateUserOpSignature(id, userOp, userOpHash, userOp.signature, msg.sender);
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
        return _validateSignature(id, hash, sig, msg.sender);
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

    // ==================== Internal Shared Logic ====================

    /**
     * @notice Internal function to validate user operation signatures
     * @dev Shared logic for both installed and stateless validator modes
     *
     *      SECURITY: Split Signature Scheme
     *      The first N-1 signatures verify a proposalHash (EIP-712 typed data covering
     *      account, id, callData, and nonce). The last signature MUST verify the full
     *      userOpHash to bind the complete UserOp (including gas fields).
     *      This prevents a scenario where guardians approve a proposal but an attacker
     *      manipulates gas parameters in the final UserOp.
     *      A double-counting check ensures a guardian who signed both the proposalHash
     *      and userOpHash only has their weight counted once.
     */
    function _validateUserOpSignature(
        bytes32 id,
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        bytes calldata sig,
        address account
    ) internal returns (uint256) {
        WeightedECDSASignerStorage storage strg = weightedStorage[id][account];
        if (strg.threshold == 0) {
            return SIG_VALIDATION_FAILED_UINT;
        }

        // Create EIP712 hash with visible fields: account, id, calldata, nonce
        bytes32 proposalHash = _hashTypedData(
            keccak256(
                abi.encode(
                    PROPOSAL_TYPEHASH,
                    userOp.sender, // account address
                    id, // id
                    keccak256(userOp.callData), // calldata hash
                    userOp.nonce // nonce
                )
            )
        );

        if (sig.length % 65 != 0) {
            return SIG_VALIDATION_FAILED_UINT;
        }

        uint256 sigCount = sig.length / 65;
        if (sigCount == 0) {
            return SIG_VALIDATION_FAILED_UINT;
        }

        uint256 totalWeight = 0;
        uint256 threshold = strg.threshold;
        address signer;
        address lastSigner = address(0);

        // Track proposalHash signers to prevent double-counting with userOpHash signer
        address[] memory proposalSigners = new address[](sigCount - 1);

        // Process all signatures except the last one (they sign proposalHash)
        // Signers must be in strictly ascending order to prevent reuse
        // NOTE: No early return - must always verify userOpHash signature
        for (uint256 i = 0; i < sigCount - 1; i++) {
            signer = ECDSA.tryRecoverCalldata(proposalHash, sig[i * 65:(i + 1) * 65]);

            // Enforce sorted order to prevent signature reuse
            require(signer > lastSigner, "Signers not sorted");
            lastSigner = signer;
            proposalSigners[i] = signer;

            uint24 guardianWeight = guardian[signer][id][account].weight;
            // Revert if non-last signer has zero weight (prevents gas griefing)
            if (guardianWeight == 0) {
                revert ZeroWeightSigner();
            }
            totalWeight += guardianWeight;
            // No early return here - must verify userOpHash signature
        }

        // Last signature MUST verify userOpHash to bind the full userOp
        // This prevents malleability of gas fields and other userOp parameters
        // NOTE: use this with ep > 0.7 only, for ep <= 0.7, need to use toEthSignedMessageHash
        signer = ECDSA.tryRecoverCalldata(userOpHash, sig[sig.length - 65:]);

        uint24 lastWeight = guardian[signer][id][account].weight;
        // If last signer has zero weight, return validation failed (don't revert)
        if (lastWeight == 0) {
            return SIG_VALIDATION_FAILED_UINT;
        }

        // Check if userOpHash signer already signed proposalHash (prevent double-counting)
        bool alreadySigned = false;
        for (uint256 i = 0; i < proposalSigners.length; i++) {
            if (proposalSigners[i] == signer) {
                alreadySigned = true;
                break;
            }
        }

        // Only add weight if signer hasn't already contributed via proposalHash
        if (!alreadySigned) {
            totalWeight += lastWeight;
        }

        if (totalWeight >= threshold) {
            return SIG_VALIDATION_SUCCESS_UINT;
        }

        return SIG_VALIDATION_FAILED_UINT;
    }

    /**
     * @notice Internal function to validate ERC-1271 signatures
     * @dev Shared logic for both installed and stateless validator modes
     */
    function _validateSignature(bytes32 id, bytes32 hash, bytes calldata sig, address account)
        internal
        view
        returns (bytes4)
    {
        WeightedECDSASignerStorage storage strg = weightedStorage[id][account];
        if (strg.threshold == 0) {
            return ERC1271_INVALID;
        }

        uint256 sigCount = sig.length / 65;
        if (sigCount == 0) {
            return ERC1271_INVALID;
        }

        uint256 totalWeight = 0;
        address signer;
        address lastSigner = address(0);

        // Process all signatures except the last one
        for (uint256 i = 0; i < sigCount - 1; i++) {
            signer = ECDSA.tryRecoverCalldata(hash, sig[i * 65:(i + 1) * 65]);

            // Enforce sorted order to prevent signature reuse
            if (signer <= lastSigner) {
                return ERC1271_INVALID;
            }
            lastSigner = signer;

            uint24 guardianWeight = guardian[signer][id][account].weight;
            // Revert if non-last signer has zero weight (prevents gas griefing)
            if (guardianWeight == 0) {
                revert ZeroWeightSigner();
            }
            totalWeight += guardianWeight;
            if (totalWeight >= strg.threshold) {
                return ERC1271_MAGICVALUE;
            }
        }

        // Process last signature
        signer = ECDSA.tryRecoverCalldata(hash, sig[sig.length - 65:]);
        if (signer <= lastSigner) {
            return ERC1271_INVALID;
        }
        uint24 lastWeight = guardian[signer][id][account].weight;
        // If last signer has zero weight, return invalid (don't revert)
        if (lastWeight == 0) {
            return ERC1271_INVALID;
        }
        totalWeight += lastWeight;
        if (totalWeight >= strg.threshold) {
            return ERC1271_MAGICVALUE;
        }

        return ERC1271_INVALID;
    }

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
