// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IAccountExecute} from "account-abstraction/interfaces/IAccountExecute.sol";
import {IERC7579Execution} from "openzeppelin-contracts/contracts/interfaces/draft-IERC7579.sol";
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
        uint48 gracePeriod; // Period after validAfter during which only owner can execute/cancel
        bool initialized;
    }

    struct Proposal {
        ProposalStatus status;
        uint48 validAfter; // Timestamp when timelock passes (grace period starts)
        uint48 graceEnd; // Timestamp when grace period ends (public execution allowed)
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
        address indexed wallet, bytes32 indexed id, uint256 delay, uint256 expirationPeriod, uint256 gracePeriod
    );

    error InvalidDelay();
    error InvalidExpirationPeriod();
    error InvalidGracePeriod();
    error ProposalNotPending();
    error OnlyAccount();
    error ParametersTooLarge();

    /**
     * @notice Install the timelock policy
     * @param _data Encoded: (uint48 delay, uint48 expirationPeriod, uint48 gracePeriod)
     */
    function _policyOninstall(bytes32 id, bytes calldata _data) internal override {
        (uint48 delay, uint48 expirationPeriod, uint48 gracePeriod) = abi.decode(_data, (uint48, uint48, uint48));

        if (timelockConfig[id][msg.sender].initialized) {
            revert IModule.AlreadyInitialized(msg.sender);
        }

        if (delay == 0) revert InvalidDelay();
        if (expirationPeriod == 0) revert InvalidExpirationPeriod();
        if (gracePeriod == 0) revert InvalidGracePeriod();
        // Prevent uint48 overflow: uint48(block.timestamp) + delay + gracePeriod + expirationPeriod
        if (uint256(delay) + uint256(gracePeriod) + uint256(expirationPeriod) > type(uint48).max - block.timestamp) {
            revert ParametersTooLarge();
        }

        // Increment epoch to invalidate any proposals from previous installations
        currentEpoch[id][msg.sender]++;

        timelockConfig[id][msg.sender] =
            TimelockConfig({delay: delay, expirationPeriod: expirationPeriod, gracePeriod: gracePeriod, initialized: true});

        emit TimelockConfigUpdated(msg.sender, id, delay, expirationPeriod, gracePeriod);
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
     * @dev Only the account itself can cancel proposals to prevent griefing
     * @param id The policy ID
     * @param account The account address
     * @param callData The calldata of the proposal
     * @param nonce The nonce of the proposal
     */
    function cancelProposal(bytes32 id, address account, bytes calldata callData, uint256 nonce) external {
        // Only the account itself can cancel its own proposals
        if (msg.sender != account) revert OnlyAccount();

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
        uint48 graceEnd = validAfter + config.gracePeriod;
        uint48 validUntil = graceEnd + config.expirationPeriod;

        // Create userOp key for storage lookup (using PROPOSAL calldata and nonce, not current userOp)
        bytes32 userOpKey = keccak256(abi.encode(userOp.sender, keccak256(proposalCallData), proposalNonce));

        Proposal storage proposal = proposals[userOpKey][id][account];

        if (proposal.status != ProposalStatus.None) {
            return SIG_VALIDATION_FAILED_UINT;
        }

        // Create proposal with current epoch
        proposals[userOpKey][id][account] =
            Proposal({status: ProposalStatus.Pending, validAfter: validAfter, graceEnd: graceEnd, validUntil: validUntil, epoch: currentEpoch[id][account]});

        emit ProposalCreated(account, id, userOpKey, validAfter, validUntil);
        return _packValidationData(0, 0);
    }

    /**
     * @notice Handle proposal execution from userOp
     * @dev Returns graceEnd as validAfter to prevent execution during grace period.
     *      This gives the owner time to cancel proposals without race conditions.
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

        // Return graceEnd (not validAfter) as the earliest execution time
        // This prevents race conditions by ensuring the owner has a grace period to cancel
        return _packValidationData(proposal.graceEnd, proposal.validUntil);
    }

    /**
     * @notice Check if calldata is a no-op operation
     * @dev Valid no-ops:
     *      1. Empty calldata
     *      2. ERC-7579 execute(CALL, self, 0, "")
     *      3. ERC-7579 execute(CALL, address(0), 0, "")
     *      4. executeUserOp with empty calldata
     */
    function _isNoOpCalldata(bytes calldata callData) internal view returns (bool) {
        // 1. Empty calldata is a no-op
        if (callData.length == 0) return true;

        // Need at least 4 bytes for selector
        if (callData.length < 4) return false;

        bytes4 selector = bytes4(callData[0:4]);

        // 2. Check for ERC-7579 execute(bytes32 mode, bytes calldata executionCalldata)
        if (selector == IERC7579Execution.execute.selector) {
            return _isNoOpERC7579Execute(callData);
        }

        // 3. Check for executeUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        if (selector == IAccountExecute.executeUserOp.selector) {
            return _isNoOpExecuteUserOp(callData);
        }

        // Not a recognized no-op
        return false;
    }

    /**
     * @notice Check if ERC-7579 execute call is a no-op
     * @dev Valid: execute(CALL, self/address(0), 0, "")
     */
    function _isNoOpERC7579Execute(bytes calldata callData) internal view returns (bool) {
        // execute(bytes32 mode, bytes calldata executionCalldata)
        // ABI layout: 4 (selector) + 32 (mode) + 32 (offset) + 32 (length) + data
        if (callData.length < 100) return false;

        // Only accept single call mode (callType = first byte of mode must be 0x00).
        // Prevents delegatecall (0xFE) or batch (0x01) payloads from being treated as no-ops.
        if (callData[4] != 0x00) return false;

        // Offset to executionCalldata: 2 head slots (mode + offset) = 64
        uint256 offset = uint256(bytes32(callData[36:68]));
        if (offset != 64) return false;

        // Decode the length of executionCalldata
        uint256 execDataLength = uint256(bytes32(callData[68:100]));

        // ERC-7579 single execution uses compact format (no length prefix):
        // executionCalldata = abi.encodePacked(target, value, calldata)
        // target (20 bytes) + value (32 bytes) = 52 bytes with no inner calldata
        if (execDataLength != 52) return false;

        if (callData.length < 152) return false;

        // Extract target address (first 20 bytes of executionCalldata)
        address target = address(bytes20(callData[100:120]));

        // Check if target is self or address(0)
        if (target != msg.sender && target != address(0)) return false;

        // Extract value (next 32 bytes)
        uint256 value = uint256(bytes32(callData[120:152]));

        // Value must be 0
        return value == 0;
    }

    /**
     * @notice Check if executeUserOp call is a no-op
     * @dev Valid: executeUserOp("", bytes32)
     */
    function _isNoOpExecuteUserOp(bytes calldata callData) internal pure returns (bool) {
        // executeUserOp(bytes calldata userOp, bytes32 userOpHash)
        // Format: 4 (selector) + 32 (userOp offset=64) + 32 (userOpHash) + 32 (userOp length) + userOp data
        if (callData.length < 100) return false;

        // Decode offset to userOp data (should be 64: past 2 head slots)
        uint256 offset = uint256(bytes32(callData[4:36]));
        if (offset != 64) return false;

        // userOpHash is at bytes 36-68 (we don't validate it)

        // Decode userOp length
        uint256 userOpLength = uint256(bytes32(callData[68:100]));

        // UserOp must be empty
        return userOpLength == 0;
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

        // Check if this is a proposal creation request
        // Criteria: calldata is a no-op AND signature has proposal data (length >= 65)
        if (_isNoOpCalldata(userOp.callData) && sig.length >= 65) {
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
     * @return validAfter When the timelock passes (grace period starts)
     * @return graceEnd When the grace period ends (public execution allowed)
     * @return validUntil When the proposal expires
     */
    function getProposal(address account, bytes calldata callData, uint256 nonce, bytes32 id, address wallet)
        external
        view
        returns (ProposalStatus status, uint256 validAfter, uint256 graceEnd, uint256 validUntil)
    {
        bytes32 userOpKey = keccak256(abi.encode(account, keccak256(callData), nonce));
        Proposal storage proposal = proposals[userOpKey][id][wallet];
        return (proposal.status, proposal.validAfter, proposal.graceEnd, proposal.validUntil);
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
