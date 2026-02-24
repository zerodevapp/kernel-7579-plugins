// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IAccountExecute} from "account-abstraction/interfaces/IAccountExecute.sol";
import {IERC7579Execution} from "openzeppelin-contracts/contracts/interfaces/draft-IERC7579.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";
import {IModule, IStatelessValidator, IStatelessValidatorWithSender} from "src/interfaces/IERC7579Modules.sol";
import {PolicyBase} from "src/base/PolicyBase.sol";
import {
    MODULE_TYPE_POLICY,
    MODULE_TYPE_STATELESS_VALIDATOR,
    MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER,
    SIG_VALIDATION_FAILED_UINT
} from "src/types/Constants.sol";

/**
 * @title TimelockPolicy
 * @notice A policy module that enforces time-delayed execution of transactions for enhanced security
 * @dev Users must first create a proposal, wait for the timelock delay, then execute
 */
contract TimelockPolicy is PolicyBase, IStatelessValidator, IStatelessValidatorWithSender {
    enum ProposalStatus {
        None, // Proposal doesn't exist
        Pending, // Clock started, waiting for timelock
        Executed, // Proposal executed
        Cancelled // Proposal cancelled
    }

    struct TimelockConfig {
        uint48 delay; // Timelock delay in seconds
        uint48 expirationPeriod; // How long after validAfter the proposal remains valid
        address guardian; // Address that can cancel proposals without timelock (address(0) = no guardian)
        bool initialized;
    }

    struct Proposal {
        ProposalStatus status;
        uint48 validAfter; // Timestamp when timelock passes and proposal becomes executable
        uint48 validUntil; // Timestamp when proposal expires
        uint256 epoch; // Epoch when proposal was created
    }

    // Storage: id => wallet => config
    mapping(bytes32 => mapping(address => TimelockConfig)) public timelockConfig;

    // Storage: id => wallet => epoch (persists across uninstall/reinstall)
    mapping(bytes32 => mapping(address => uint256)) public currentEpoch;

    // Storage: userOpKey => id => wallet => proposal
    // userOpKey = keccak256(abi.encode(account, keccak256(callData), nonce))
    mapping(bytes32 => mapping(bytes32 => mapping(address => Proposal))) public proposals;

    event ProposalCreated(
        address indexed wallet, bytes32 indexed id, bytes32 indexed proposalHash, uint256 validAfter, uint256 validUntil
    );

    event ProposalExecuted(address indexed wallet, bytes32 indexed id, bytes32 indexed proposalHash);

    event ProposalCancelled(address indexed wallet, bytes32 indexed id, bytes32 indexed proposalHash);

    event TimelockConfigUpdated(
        address indexed wallet, bytes32 indexed id, uint256 delay, uint256 expirationPeriod, address guardian
    );

    error InvalidDelay();
    error InvalidExpirationPeriod();
    error ProposalNotPending();
    error OnlyAccount();
    error ParametersTooLarge();

    /**
     * @notice Install the timelock policy
     * @param _data Encoded: (uint48 delay, uint48 expirationPeriod, address guardian)
     */
    function _policyOninstall(bytes32 id, bytes calldata _data) internal override {
        (uint48 delay, uint48 expirationPeriod, address guardian) = abi.decode(_data, (uint48, uint48, address));

        if (timelockConfig[id][msg.sender].initialized) {
            revert IModule.AlreadyInitialized(msg.sender);
        }

        if (delay == 0) revert InvalidDelay();
        if (expirationPeriod == 0) revert InvalidExpirationPeriod();
        // Prevent uint48 overflow: uint48(block.timestamp) + delay + expirationPeriod
        if (uint256(delay) + uint256(expirationPeriod) > type(uint48).max - block.timestamp) {
            revert ParametersTooLarge();
        }

        // Increment epoch to invalidate any proposals from previous installations
        currentEpoch[id][msg.sender]++;

        timelockConfig[id][msg.sender] =
            TimelockConfig({delay: delay, expirationPeriod: expirationPeriod, guardian: guardian, initialized: true});

        emit TimelockConfigUpdated(msg.sender, id, delay, expirationPeriod, guardian);
    }

    /**
     * @notice Uninstall the timelock policy
     */
    function _policyOnUninstall(bytes32 id, bytes calldata) internal override {
        if (!timelockConfig[id][msg.sender].initialized) {
            revert IModule.NotInitialized(msg.sender);
        }

        delete timelockConfig[id][msg.sender];
    }

    /**
     * @notice Check if this module is a specific type
     * @dev Supports policy and stateless validator types
     */
    function isModuleType(uint256 moduleTypeId) external pure override(IModule, PolicyBase) returns (bool) {
        return moduleTypeId == MODULE_TYPE_POLICY || moduleTypeId == MODULE_TYPE_STATELESS_VALIDATOR
            || moduleTypeId == MODULE_TYPE_STATELESS_VALIDATOR_WITH_SENDER;
    }

    /**
     * @notice Cancel a pending proposal
     * @dev Only the account itself or its designated guardian can cancel proposals
     * @param id The policy ID
     * @param account The account address
     * @param callData The calldata of the proposal
     * @param nonce The nonce of the proposal
     */
    function cancelProposal(bytes32 id, address account, bytes calldata callData, uint256 nonce) external {
        // Only the account itself or the designated guardian can cancel proposals
        address guardianAddr = timelockConfig[id][account].guardian;
        if (msg.sender != account && (guardianAddr == address(0) || msg.sender != guardianAddr)) revert OnlyAccount();

        TimelockConfig storage config = timelockConfig[id][account];
        if (!config.initialized) revert IModule.NotInitialized(account);

        // Create userOp key to look up the proposal
        bytes32 userOpKey = keccak256(abi.encode(account, keccak256(callData), nonce));

        Proposal storage proposal = proposals[userOpKey][id][account];
        if (proposal.status != ProposalStatus.Pending) {
            revert ProposalNotPending();
        }

        proposal.status = ProposalStatus.Cancelled;

        emit ProposalCancelled(account, id, userOpKey);
    }

    /**
     * @notice Check user operation against timelock policy
     * @dev Called by the smart account during validation phase
     *      If calldata is a no-op and signature contains proposal data, creates a proposal
     *      Otherwise, executes an existing proposal
     * @param id The policy ID
     * @param userOp The user operation to validate
     * @return validationData Packed validation data (ERC-4337 format)
     *         Format: <validAfter (6 bytes)><validUntil (6 bytes)><authorizer/result (20 bytes)>
     *         Returns 1 if validation fails or proposal created
     */
    function checkUserOpPolicy(bytes32 id, PackedUserOperation calldata userOp)
        external
        payable
        override
        returns (uint256)
    {
        return _validateUserOpPolicy(id, userOp, userOp.signature, msg.sender);
    }

    /**
     * @notice Handle proposal creation from a no-op UserOp
     * @dev Called when the session key holder submits a no-op UserOp with proposal data in the signature.
     *      Creates a new Pending proposal with the timelock clock started.
     *      Signature format: [callDataLength(32)][callData][nonce(32)][remaining sig data]
     */
    function _handleProposalCreationInternal(
        bytes32 id,
        PackedUserOperation calldata userOp,
        TimelockConfig storage config,
        bytes calldata sig,
        address account
    ) internal returns (uint256) {
        // Decode proposal data from signature
        // Format: [callDataLength(32 bytes)][callData][nonce(32 bytes)][...]
        uint256 callDataLength = uint256(bytes32(sig[0:32]));

        // Validate signature has enough data (check callDataLength first to prevent overflow)
        if (callDataLength > sig.length || sig.length < 64 + callDataLength) return SIG_VALIDATION_FAILED_UINT;

        bytes calldata proposalCallData = sig[32:32 + callDataLength];
        uint256 proposalNonce = uint256(bytes32(sig[32 + callDataLength:64 + callDataLength]));

        // Calculate proposal timing
        uint48 validAfter = uint48(block.timestamp) + config.delay;
        uint48 validUntil = validAfter + config.expirationPeriod;

        // Create userOp key for storage lookup (using PROPOSAL calldata and nonce, not current userOp)
        bytes32 userOpKey = keccak256(abi.encode(userOp.sender, keccak256(proposalCallData), proposalNonce));

        Proposal storage proposal = proposals[userOpKey][id][account];

        if (proposal.status != ProposalStatus.None) {
            return SIG_VALIDATION_FAILED_UINT;
        }

        // Create proposal with current epoch
        proposals[userOpKey][id][account] = Proposal({
            status: ProposalStatus.Pending,
            validAfter: validAfter,
            validUntil: validUntil,
            epoch: currentEpoch[id][account]
        });

        emit ProposalCreated(account, id, userOpKey, validAfter, validUntil);
        return _packValidationData(0, 0);
    }

    /**
     * @notice Handle proposal execution from userOp
     * @dev Returns validAfter/validUntil so EntryPoint enforces the timelock window.
     *      The guardian mechanism provides the cancellation path (not a grace period).
     */
    function _handleProposalExecutionInternal(bytes32 id, PackedUserOperation calldata userOp, address account)
        internal
        returns (uint256)
    {
        // Create userOp key to look up the proposal
        bytes32 userOpKey = keccak256(abi.encode(userOp.sender, keccak256(userOp.callData), userOp.nonce));

        Proposal storage proposal = proposals[userOpKey][id][account];

        // Check proposal exists and is pending
        if (proposal.status != ProposalStatus.Pending) return SIG_VALIDATION_FAILED_UINT;

        // Check proposal is from current epoch (not a stale proposal from previous installation)
        if (proposal.epoch != currentEpoch[id][account]) return SIG_VALIDATION_FAILED_UINT;

        // Mark as executed
        proposal.status = ProposalStatus.Executed;

        emit ProposalExecuted(account, id, userOpKey);

        return _packValidationData(proposal.validAfter, proposal.validUntil);
    }

    /**
     * @notice Check if calldata is a no-op operation
     * @dev Recognizes 4 forms of no-op:
     *      1. Empty calldata
     *      2. ERC-7579 execute(mode=0x00, abi.encodePacked(address(0), uint256(0))) — single-call, zero-target, zero-value, no inner calldata
     *      3. executeUserOp + empty inner calldata (just the 4-byte selector)
     *      4. executeUserOp + ERC-7579 execute no-op (selector + form 2)
     */
    function _isNoOpCalldata(bytes calldata callData) internal pure returns (bool) {
        uint256 len = callData.length;

        // Case 1: Empty calldata
        if (len == 0) return true;

        // Case 2: ERC-7579 execute with minimal no-op execution data
        if (_isNoOpERC7579Execute(callData)) return true;

        // Cases 3 & 4: executeUserOp wrapper
        if (len >= 4 && bytes4(callData[0:4]) == IAccountExecute.executeUserOp.selector) {
            // Case 3: executeUserOp + empty (just the selector, no inner data)
            if (len == 4) return true;
            // Case 4: executeUserOp + ERC-7579 execute no-op
            if (_isNoOpERC7579Execute(callData[4:])) return true;
        }

        return false;
    }

    /**
     * @notice Check if calldata is an ERC-7579 execute call that performs a zero-value no-op
     * @dev execute(bytes32 mode, bytes calldata executionCalldata) where:
     *      - mode is CALLTYPE_SINGLE (not batch/delegatecall)
     *      - executionCalldata decodes via LibERC7579.decodeSingle() to (address(0), 0, empty)
     *      - target is address(0) (a non-zero target could trigger receive()/fallback() side effects)
     *      - value is 0 (no ETH transfer)
     *      - no inner calldata
     */
    function _isNoOpERC7579Execute(bytes calldata callData) internal pure returns (bool) {
        // Minimum: selector(4) + mode(32) + ABI bytes header: offset(32) + length(32) = 100
        if (callData.length < 100) return false;
        if (bytes4(callData[0:4]) != IERC7579Execution.execute.selector) return false;

        // Decode mode and check call type via LibERC7579
        bytes32 mode = bytes32(callData[4:36]);
        if (LibERC7579.getCallType(mode) != LibERC7579.CALLTYPE_SINGLE) return false;

        // Extract executionCalldata from ABI-encoded bytes parameter
        uint256 offset = uint256(bytes32(callData[36:68]));
        uint256 lenPos = 4 + offset;
        if (callData.length < lenPos + 32) return false;
        uint256 dataLen = uint256(bytes32(callData[lenPos:lenPos + 32]));
        uint256 dataPos = lenPos + 32;
        if (callData.length < dataPos + dataLen) return false;

        bytes calldata executionCalldata = callData[dataPos:dataPos + dataLen];

        // decodeSingle requires length > 0x33 (target(20) + value(32) minimum)
        if (executionCalldata.length <= 0x33) return false;

        // Use LibERC7579 to decode — same decoding path the account uses
        (address target, uint256 val, bytes calldata innerCalldata) = LibERC7579.decodeSingle(executionCalldata);

        // No-op: zero target, zero value, and no inner calldata
        return target == address(0) && val == 0 && innerCalldata.length == 0;
    }

    /**
     * @notice Pack validAfter and validUntil into validation data (ERC-4337 format)
     * @dev Format: <validAfter (6 bytes)><validUntil (6 bytes)><authorizer/result (20 bytes)>
     *      Bits 0-159:   authorizer (address) or 0 for success, 1 for failure
     *      Bits 160-207: validUntil (uint48)
     *      Bits 208-255: validAfter (uint48)
     * @param validAfter Timestamp when the operation becomes valid
     * @param validUntil Timestamp when the operation expires
     * @return validationData Packed validation data
     */
    function _packValidationData(uint48 validAfter, uint48 validUntil) internal pure returns (uint256) {
        return uint256(validAfter) << 208 | uint256(validUntil) << 160;
    }

    /**
     * @notice Check signature against timelock policy (for ERC-1271)
     * @dev TimelockPolicy does not support ERC-1271 signature validation - always reverts
     */
    function checkSignaturePolicy(bytes32, address, bytes32, bytes calldata) external pure override returns (uint256) {
        revert("TimelockPolicy: signature validation not supported");
    }

    function validateSignatureWithData(bytes32, bytes calldata, bytes calldata)
        external
        pure
        override(IStatelessValidator)
        returns (bool)
    {
        revert("TimelockPolicy: stateless signature validation not supported");
    }

    function validateSignatureWithDataWithSender(address, bytes32, bytes calldata, bytes calldata)
        external
        pure
        override(IStatelessValidatorWithSender)
        returns (bool)
    {
        revert("TimelockPolicy: stateless signature validation not supported");
    }

    // ==================== Internal Shared Logic ====================

    /**
     * @notice Internal function to validate user operation policy
     * @dev Shared logic for both installed and stateless validator modes
     */
    function _validateUserOpPolicy(bytes32 id, PackedUserOperation calldata userOp, bytes calldata sig, address account)
        internal
        returns (uint256)
    {
        TimelockConfig storage config = timelockConfig[id][account];
        if (!config.initialized) return SIG_VALIDATION_FAILED_UINT;

        // Check if this is a proposal creation request (no-op calldata with proposal data in sig)
        if (_isNoOpCalldata(userOp.callData)) {
            return _handleProposalCreationInternal(id, userOp, config, sig, account);
        }

        // Otherwise, this is a proposal execution request
        return _handleProposalExecutionInternal(id, userOp, account);
    }

    /**
     * @notice Get proposal details
     * @param account The account address
     * @param callData The calldata
     * @param nonce The nonce
     * @param id The policy ID
     * @param wallet The wallet address
     * @return status The proposal status
     * @return validAfter When the timelock passes and proposal becomes executable
     * @return validUntil When the proposal expires
     */
    function getProposal(address account, bytes calldata callData, uint256 nonce, bytes32 id, address wallet)
        external
        view
        returns (ProposalStatus status, uint256 validAfter, uint256 validUntil)
    {
        bytes32 userOpKey = keccak256(abi.encode(account, keccak256(callData), nonce));
        Proposal storage proposal = proposals[userOpKey][id][wallet];
        return (proposal.status, proposal.validAfter, proposal.validUntil);
    }

    /**
     * @notice Compute the user operation key for storage lookup
     * @param account The account address
     * @param callData The calldata
     * @param nonce The nonce
     * @return The user operation key
     */
    function computeUserOpKey(address account, bytes calldata callData, uint256 nonce) external pure returns (bytes32) {
        return keccak256(abi.encode(account, keccak256(callData), nonce));
    }
}
