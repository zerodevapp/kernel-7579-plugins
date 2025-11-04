// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {ECDSA} from "solady/utils/ECDSA.sol";
import {EIP712} from "solady/utils/EIP712.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IValidator} from "src/interfaces/IERC7579Modules.sol";
import {
    ERC1271_MAGICVALUE,
    ERC1271_INVALID,
    SIG_VALIDATION_FAILED_UINT,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_HOOK
} from "src/types/Constants.sol";

struct WeightedECDSASignerStorage {
    uint24 totalWeight;
    uint24 threshold;
    address firstGuardian;
}

struct GuardianStorage {
    uint24 weight;
    address nextGuardian;
}

enum ProposalStatus {
    Ongoing, // all proposal is ongoing by default
    Approved,
    Rejected,
    Executed
}

struct ProposalStorage {
    ProposalStatus status;
}

enum VoteStatus {
    NA,
    Approved
}

struct VoteStorage {
    VoteStatus status;
}

contract WeightedECDSASigner is EIP712, IValidator {
    mapping(bytes32 id => mapping(address kernel => WeightedECDSASignerStorage)) public weightedStorage;
    mapping(address guardian => mapping(bytes32 id => mapping(address kernel => GuardianStorage))) public guardian;
    mapping(bytes32 callDataAndNonceHash => mapping(bytes32 id => mapping(address kernel => ProposalStorage))) public proposalStatus;
    mapping(bytes32 callDataAndNonceHash => mapping(address guardian => mapping(bytes32 id => mapping(address kernel => VoteStorage)))) public
        voteStatus;

    event GuardianAdded(address indexed guardian, address indexed kernel, uint24 weight);
    event GuardianRemoved(address indexed guardian, address indexed kernel);

    function _domainNameAndVersion() internal pure override returns (string memory, string memory) {
        return ("WeightedECDSASigner", "0.0.2");
    }

    function _signerOninstall(bytes32 id, bytes calldata _data) internal payable override {
        (address[] memory _guardians, uint24[] memory _weights, uint24 _threshold) =
            abi.decode(_data, (address[], uint24[], uint24));
        require(_guardians.length == _weights.length, "Length mismatch");
        weightedStorage[id][msg.sender].firstGuardian = msg.sender;
        for (uint256 i = 0; i < _guardians.length; i++) {
            require(_guardians[i] != msg.sender, "Guardian cannot be self");
            require(_guardians[i] != address(0), "Guardian cannot be 0");
            require(_weights[i] != 0, "Weight cannot be 0");
            require(guardian[_guardians[i]][msg.sender].weight == 0, "Guardian already enabled");
            guardian[_guardians[i]][msg.sender] =
                GuardianStorage({weight: _weights[i], nextGuardian: weightedStorage[msg.sender].firstGuardian});
            weightedStorage[msg.sender].firstGuardian = _guardians[i];
            weightedStorage[msg.sender].totalWeight += _weights[i];
            emit GuardianAdded(_guardians[i], msg.sender, _weights[i]);
        }
        weightedStorage[msg.sender].threshold = _threshold;
    }

    function _signerOnUninstall(bytes32 id, bytes calldata) internal payable override {
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

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_SIGNER || moduleTypeId == MODULE_TYPE_STATELESS_VALIDATOR || moduleTypeId == MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER;
    }

    function isInitialized(address smartAccount) external view returns (bool) {
        return _isInitialized(smartAccount);
    }

    function _isInitialized(address smartAccount) internal view returns (bool) {
        return weightedStorage[smartAccount].totalWeight != 0;
    }

    function checkUserOpSignature(bytes32 id, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        override
        returns (uint256)
    {
        bytes32 callDataAndNonceHash = keccak256(abi.encode(userOp.sender, userOp.callData, userOp.nonce));
        ProposalStorage storage proposal = proposalStatus[callDataAndNonceHash][msg.sender];
        WeightedECDSASigner storage strg = weightedStorage[msg.sender];
        if (strg.threshold == 0) {
            return SIG_VALIDATION_FAILED_UINT;
        }
        (uint256 totalWeight, bool passed) = getApproval(msg.sender, callDataAndNonceHash);
        uint256 threshold = strg.threshold;
        if (proposal.status == ProposalStatus.Ongoing && !passed) {
            bytes calldata sig = userOp.signature;
            // parse sig with 65 bytes
            uint256 sigCount = sig.length / 65;
            require(sigCount > 0, "No sig");
            address signer;
            VoteStorage storage vote;
            for (uint256 i = 0; i < sigCount - 1 && !passed; i++) {
                signer = ECDSA.recover(
                    _hashTypedData(
                        keccak256(abi.encode(keccak256("Approve(bytes32 callDataAndNonceHash)"), callDataAndNonceHash))
                    ),
                    sig[i * 65:(i + 1) * 65]
                );
                vote = voteStatus[callDataAndNonceHash][signer][msg.sender];
                if (vote.status != VoteStatus.NA) {
                    continue;
                } // skip if already voted
                vote.status = VoteStatus.Approved;
                totalWeight += guardian[signer][msg.sender].weight;
                if (totalWeight >= threshold) {
                    passed = true;
                }
            }
            // userOpHash verification for the last sig
            // NOTE: use this with ep > 0.7 only, for ep <= 0.7, need to use toEthSignedMessageHash
            signer = ECDSA.recover(userOpHash, sig[sig.length - 65:]);
            vote = voteStatus[callDataAndNonceHash][signer][msg.sender];
            if (vote.status == VoteStatus.NA) {
                vote.status = VoteStatus.Approved;
                totalWeight += guardian[signer][msg.sender].weight;
                if (totalWeight >= threshold) {
                    passed = true;
                }
            }
            if (passed && guardian[signer][msg.sender].weight != 0) {
                proposal.status = ProposalStatus.Executed;
                return SIG_VALIDATION_SUCCESS_UINT;
            }
        } else if (proposal.status == ProposalStatus.Approved || passed) {
            address signer = ECDSA.recover(ECDSA.toEthSignedMessageHash(userOpHash), userOp.signature);
            if (guardian[signer][msg.sender].weight != 0) {
                proposal.status = ProposalStatus.Executed;
                return SIG_VALIDATION_SUCCESS_UINT;
            }
        }
        return SIG_VALIDATION_FAILED_UINT;
    }

    function getApproval(address kernel, bytes32 id, bytes32 hash) public view returns (uint256 approvals, bool passed) {
        WeightedECDSAValidatorStorage storage strg = weightedStorage[id][kernel];
        for (
            address currentGuardian = strg.firstGuardian;
            currentGuardian != address(0);
            currentGuardian = guardian[currentGuardian][id][kernel].nextGuardian
        ) {
            if (voteStatus[hash][currentGuardian][kernel].status == VoteStatus.Approved) {
                approvals += guardian[currentGuardian][id][kernel].weight;
            }
        }
        ProposalStorage storage proposal = proposalStatus[hash][kernel];
        if (proposal.status == ProposalStatus.Rejected) {
            passed = false;
        } else {
            passed = approvals >= strg.threshold;
        }
    }

    function checkSignature(bytes32 id, address, bytes32 hash, bytes calldata sig) external view returns (bytes4) {
        WeightedECDSAValidatorStorage storage strg = weightedStorage[id][msg.sender];
        if (strg.threshold == 0) {
            return ERC1271_INVALID;
        }

        uint256 sigCount = sig.length / 65;
        if (sigCount == 0) {
            return ERC1271_INVALID;
        }
        uint256 totalWeight = 0;
        address signer;
        for (uint256 i = 0; i < sigCount; i++) {
            signer = ECDSA.tryRecoverCalldata(hash, sig[i * 65:(i + 1) * 65]);
            totalWeight += guardian[signer][id][msg.sender].weight;
            if (totalWeight >= strg.threshold) {
                return ERC1271_MAGICVALUE;
            }
        }
        return ERC1271_INVALID;
    }
}