// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "kernel/types/Types.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {MerkleProofLib} from "solady/utils/MerkleProofLib.sol";
import {EIP712} from "solady/utils/EIP712.sol";
import {PackedUserOperation} from "kernel/interfaces/PackedUserOperation.sol";
import {IValidator} from "kernel/interfaces/IERC7579Modules.sol";
import {
    ERC1271_MAGICVALUE,
    ERC1271_INVALID,
    SIG_VALIDATION_FAILED_UINT,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_HOOK
} from "kernel/types/Constants.sol";
import {WebAuthn} from "./WebAuthn.sol";

struct WeightedValidatorStorage {
    uint24 totalWeight;
    uint24 threshold;
    uint48 delay;
    uint32 guardianLength;
}

struct GuardianStorage {
    bytes1 guardianType; // 0x01 indicates k1, 0x02 indicates r1
    uint24 weight;
    bytes encodedPublicKey;
}

enum ProposalStatus {
    Ongoing, // all proposal is ongoing by default
    Approved,
    Rejected,
    Executed
}

struct ProposalStorage {
    ProposalStatus status;
    ValidAfter validAfter;
    uint24 approvals;
}

enum VoteStatus {
    NA,
    Approved
}

struct VoteStorage {
    VoteStatus status;
}

contract WeightedValidator is EIP712, IValidator {
    // The location of the challenge in the clientDataJSON
    uint256 constant CHALLENGE_LOCATION = 23;
    mapping(address kernel => WeightedValidatorStorage) public weightedStorage;
    mapping(uint256 guardianIndex => mapping(address kernel => GuardianStorage)) public guardian;
    mapping(bytes32 callDataAndNonceHash => mapping(address kernel => ProposalStorage)) public proposalStatus;
    mapping(bytes32 callDataAndNonceHash => mapping(uint256 guardianIndex => mapping(address kernel => VoteStorage)))
        public voteStatus;

    event GuardianAddedK1(address indexed kernel, uint256 indexed index, address indexed guardian, uint24 weight);
    event GuardianRemovedK1(address indexed kernel, uint256 indexed index, address indexed guardian);
    event GuardianAddedR1(
        address indexed kernel,
        uint256 indexed index,
        bytes32 indexed authenticatorIdHash,
        uint256 pubKeyX,
        uint256 pubKeyY,
        uint24 weight
    );
    event GuardianRemovedR1(address indexed kernel, uint256 indexed index, bytes32 indexed authenticatorIdHash);

    error NotSupportedSignatureType();
    error WrongGuardianDataLength();
    error InvalidSignature(uint256 i);

    function _domainNameAndVersion() internal pure override returns (string memory, string memory) {
        return ("MultiChainWeightedValidator", "0.0.1");
    }

    function _addGuardians(bytes[] calldata guardianData, address _kernel) internal {
        uint24 totalWeight = weightedStorage[_kernel].totalWeight;
        for (uint256 i = 0; i < guardianData.length; i++) {
            bytes calldata g = guardianData[i];
            bytes1 guardianType = bytes1(g[0]);
            uint24 weight = uint24(bytes3(g[1:4]));
            totalWeight += weight;
            if (guardianType == 0x01) {
                // k1
                if (g.length != 24) {
                    revert WrongGuardianDataLength();
                }
                guardian[i][_kernel].guardianType = bytes1(0x01);
                guardian[i][_kernel].weight = weight;
                guardian[i][_kernel].encodedPublicKey = g[4:24];
                emit GuardianAddedK1(_kernel, i, address(bytes20(g[4:24])), weight);
            } else if (guardianType == 0x02) {
                // r1
                if (g.length != 100) {
                    revert WrongGuardianDataLength();
                }
                guardian[i][_kernel].guardianType = bytes1(0x02);
                guardian[i][_kernel].weight = weight;
                guardian[i][_kernel].encodedPublicKey = g[4:100]; // this will be abi.encodePacked(x,y,authenticatorIdHash)
                emit GuardianAddedR1(
                    _kernel, i, bytes32(g[68:100]), uint256(bytes32(g[4:36])), uint256(bytes32(g[36:68])), weight
                );
            } else {
                revert NotSupportedSignatureType();
            }
        }
        weightedStorage[_kernel].totalWeight = totalWeight;
    }

    function onInstall(bytes calldata _data) external payable override {
        uint24 threshold = uint24(bytes3(_data[0:3]));
        uint48 delay = uint48(bytes6(_data[3:9]));
        bytes[] calldata guardianData = _parseCalldataArrayBytes(_data[9:]);
        _addGuardians(guardianData, msg.sender);
        require(threshold <= weightedStorage[msg.sender].totalWeight, "Threshold too high");
        weightedStorage[msg.sender].delay = delay;
        weightedStorage[msg.sender].threshold = threshold;
        weightedStorage[msg.sender].guardianLength = uint32(guardianData.length);
    }

    function _parseCalldataArrayBytes(bytes calldata _data) internal pure returns (bytes[] calldata guardianData) {
        assembly {
            guardianData.offset := add(add(_data.offset, 0x20), calldataload(_data.offset))
            guardianData.length := calldataload(sub(guardianData.offset, 0x20))
        }
    }

    function _parseSig(bytes calldata rawSig)
        internal
        pure
        returns (bytes[] calldata merkleData, bytes[] calldata signatures)
    {
        assembly {
            merkleData.offset := add(add(rawSig.offset, 32), calldataload(rawSig.offset))
            merkleData.length := calldataload(sub(merkleData.offset, 32))
            signatures.offset := add(add(rawSig.offset, 32), calldataload(add(rawSig.offset, 32)))
            signatures.length := calldataload(sub(signatures.offset, 32))
        }
    }

    function onUninstall(bytes calldata) external payable override {
        if (!_isInitialized(msg.sender)) revert NotInitialized(msg.sender);
        // TODO remove everything
    }

    function _checkK1Sig(bytes32 hash, bytes calldata sig, address signer) internal view returns (bool) {
        if (ECDSA.recover(hash, sig) == signer) {
            return true;
        }
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(hash);
        return ECDSA.recover(ethHash, sig) == signer;
    }

    function _checkR1Sig(bytes32 hash, bytes calldata sig, uint256 x, uint256 y) internal view returns (bool) {
        // decode the signature
        (
            bytes memory authenticatorData,
            string memory clientDataJSON,
            uint256 responseTypeLocation,
            uint256 r,
            uint256 s,
            bool usePrecompiled
        ) = abi.decode(sig, (bytes, string, uint256, uint256, uint256, bool));

        // verify the signature using the signature and the public key
        bool isValid = WebAuthn.verifySignature(
            abi.encodePacked(hash),
            authenticatorData,
            true,
            clientDataJSON,
            CHALLENGE_LOCATION,
            responseTypeLocation,
            r,
            s,
            x,
            y,
            usePrecompiled
        );
        return isValid;
    }

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    function isInitialized(address smartAccount) external view returns (bool) {
        return _isInitialized(smartAccount);
    }

    function _isInitialized(address smartAccount) internal view returns (bool) {
        return weightedStorage[smartAccount].totalWeight != 0;
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        override
        returns (uint256)
    {
        WeightedValidatorStorage storage validatorStrg = weightedStorage[msg.sender];
        (bytes[] calldata merkleData, bytes[] calldata signatures) = _parseSig(userOp.signature);
        bytes calldata approveMerkleData = merkleData[0];
        bytes calldata userOpMerkleData = merkleData[1];
        bytes32 callDataAndNonceHash = keccak256(abi.encode(userOp.sender, userOp.callData, userOp.nonce));
        bytes32 hashTypedData = _hashTypedData(
            keccak256(abi.encode(keccak256("Approve(bytes32 callDataAndNonceHash)"), callDataAndNonceHash))
        );
        bytes32 approveSigHash = hashTypedData;
        if (approveMerkleData.length != 0) {
            bytes32 approveMerkleRoot = bytes32(approveMerkleData[0:32]);
            bytes32[] memory approveProof = abi.decode(approveMerkleData[32:], (bytes32[]));
            require(
                MerkleProofLib.verify(approveProof, approveMerkleRoot, hashTypedData), "approve hash is not in proof"
            );
            approveSigHash = approveMerkleRoot;
        }

        uint24 currentApproval = proposalStatus[callDataAndNonceHash][msg.sender].approvals;
        uint256 i = 0;
        for (i = 0; i < signatures.length - 1; i++) {
            // last signature is for userOpHash signing
            bool sigCheck;
            (sigCheck, currentApproval) =
                _checkSigVote(callDataAndNonceHash, approveSigHash, signatures[i], currentApproval);
            if (!sigCheck) {
                revert InvalidSignature(i);
            }
        }
        // userOp Verification
        {
            // last signature to check the userOpHash
            bytes32 userOpSigHash = userOpHash;
            if (userOpMerkleData.length != 0) {
                bytes32 userOpMerkleRoot = bytes32(userOpMerkleData[0:32]);
                bytes32[] memory userOpProof = abi.decode(userOpMerkleData[32:], (bytes32[]));
                require(MerkleProofLib.verify(userOpProof, userOpMerkleRoot, userOpHash), "userOp hash is not in proof");
                userOpSigHash = userOpMerkleRoot;
            }
            bool sigCheck;
            (sigCheck, currentApproval) =
                _checkSigVote(callDataAndNonceHash, userOpSigHash, signatures[i], currentApproval);
            proposalStatus[callDataAndNonceHash][msg.sender].approvals = currentApproval;
            return sigCheck && (currentApproval >= validatorStrg.threshold) ? 0 : 1;
        }
    }

    function _checkSigVote(bytes32 callDataAndNonceHash, bytes32 hash, bytes calldata sig, uint24 currentApproval)
        internal
        returns (bool, uint24)
    {
        uint8 idx = uint8(bytes1(sig[0]));
        GuardianStorage storage strg = guardian[idx][msg.sender];
        bool sigCheck;
        if (strg.guardianType == 0x01) {
            sigCheck = _checkK1Sig(hash, sig[1:], address(bytes20(strg.encodedPublicKey)));
        } else if (strg.guardianType == 0x02) {
            (uint256 x, uint256 y) = abi.decode(strg.encodedPublicKey, (uint256, uint256));
            sigCheck = _checkR1Sig(hash, sig[1:], x, y);
        }
        VoteStorage storage voteStrg = voteStatus[callDataAndNonceHash][idx][msg.sender];
        if (voteStrg.status != VoteStatus.Approved) {
            currentApproval += strg.weight;
            voteStrg.status = VoteStatus.Approved;
        }
        return (sigCheck, currentApproval);
    }

    function _checkSig(bytes32 hash, bytes calldata sig, uint24 currentApproval) internal view returns (bool, uint24) {
        uint8 idx = uint8(bytes1(sig[0]));
        GuardianStorage storage strg = guardian[idx][msg.sender];
        bool sigCheck;
        if (strg.guardianType == 0x01) {
            sigCheck = _checkK1Sig(hash, sig[1:], address(bytes20(strg.encodedPublicKey)));
        } else if (strg.guardianType == 0x02) {
            (uint256 x, uint256 y) = abi.decode(strg.encodedPublicKey, (uint256, uint256));
            sigCheck = _checkR1Sig(hash, sig[1:], x, y);
        }
        if (sigCheck) {
            currentApproval += strg.weight;
        }
        return (sigCheck, currentApproval);
    }

    function isValidSignatureWithSender(address, bytes32 hash, bytes calldata signature)
        external
        view
        returns (bytes4)
    {
        (bytes[] calldata merkleData, bytes[] calldata signatures) = _parseSig(signature);
        bytes32 sigHash = hash;
        if (merkleData[0].length != 0) {
            bytes32 merkleRoot = bytes32(merkleData[0][0:32]);
            bytes32[] memory proof = abi.decode(merkleData[0][32:], (bytes32[]));
            require(MerkleProofLib.verify(proof, merkleRoot, hash), "sig hash is not in proof");
            sigHash = merkleRoot;
        }
        uint24 currentApproval;
        bool sigCheck;
        for (uint256 i = 0; i < signatures.length; i++) {
            (sigCheck, currentApproval) = _checkSig(sigHash, signatures[i], currentApproval);
        }
        return currentApproval >= weightedStorage[msg.sender].threshold ? ERC1271_MAGICVALUE : ERC1271_INVALID;
    }
}
