// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IAccountExecute} from "account-abstraction/interfaces/IAccountExecute.sol";
import {IERC7579Execution} from "openzeppelin-contracts/contracts/interfaces/draft-IERC7579.sol";
import {IModule} from "src/interfaces/IERC7579Modules.sol";
import {PolicyBase} from "src/base/PolicyBase.sol";

/**
 * @title TimelockPolicy
 * @notice A policy module that enforces time-delayed execution of transactions for enhanced security
 * @dev Users must first create a proposal, wait for the timelock delay, then execute
 */
contract TimelockPolicy is PolicyBase {

    enum ProposalStatus {
        None, // Proposal doesn't exist
        Pending, // Proposal created, waiting for timelock
        Executed, // Proposal executed
        Cancelled // Proposal cancelled
    }

    struct TimelockConfig {
        uint48 delay; // Timelock delay in seconds
        uint48 expirationPeriod; // How long after validAfter the proposal remains valid
        bool initialized;
    }

    struct Proposal {
        ProposalStatus status;
        uint48 validAfter; // Timestamp when proposal becomes executable
        uint48 validUntil; // Timestamp when proposal expires
    }

    // Storage: id => wallet => config
    mapping(bytes32 => mapping(address => TimelockConfig)) public timelockConfig;

    // Storage: userOpKey => id => wallet => proposal
    // userOpKey = keccak256(abi.encode(account, keccak256(callData), nonce))
    mapping(bytes32 => mapping(bytes32 => mapping(address => Proposal))) public proposals;

    // Track number of installed policies per wallet
    mapping(address => uint256) public usedIds;

    event ProposalCreated(
        address indexed wallet,
        bytes32 indexed id,
        bytes32 indexed proposalHash,
        uint256 validAfter,
        uint256 validUntil
    );

    event ProposalExecuted(address indexed wallet, bytes32 indexed id, bytes32 indexed proposalHash);

    event ProposalCancelled(address indexed wallet, bytes32 indexed id, bytes32 indexed proposalHash);

    event TimelockConfigUpdated(address indexed wallet, bytes32 indexed id, uint256 delay, uint256 expirationPeriod);

    error InvalidDelay();
    error InvalidExpirationPeriod();
    error ProposalNotFound();
    error ProposalAlreadyExists();
    error TimelockNotExpired(uint256 validAfter, uint256 currentTime);
    error ProposalExpired(uint256 validUntil, uint256 currentTime);
    error ProposalNotPending();
    error OnlyAccount();

    /**
     * @notice Install the timelock policy
     * @param _data Encoded: (uint48 delay, uint48 expirationPeriod)
     */
    function _policyOninstall(bytes32 id, bytes calldata _data) internal override {
        (uint48 delay, uint48 expirationPeriod) = abi.decode(_data, (uint48, uint48));

        if (timelockConfig[id][msg.sender].initialized) {
            revert IModule.AlreadyInitialized(msg.sender);
        }

        if (delay == 0) revert InvalidDelay();
        if (expirationPeriod == 0) revert InvalidExpirationPeriod();

        timelockConfig[id][msg.sender] =
            TimelockConfig({delay: delay, expirationPeriod: expirationPeriod, initialized: true});

        usedIds[msg.sender]++;

        emit TimelockConfigUpdated(msg.sender, id, delay, expirationPeriod);
    }

    /**
     * @notice Uninstall the timelock policy
     */
    function _policyOnUninstall(bytes32 id, bytes calldata) internal override {

        if (!timelockConfig[id][msg.sender].initialized) {
            revert IModule.NotInitialized(msg.sender);
        }

        delete timelockConfig[id][msg.sender];
        usedIds[msg.sender]--;
    }

    /**
     * @notice Check if the policy is initialized for a wallet
     */
    function isInitialized(address wallet) public view override returns (bool) {
        return usedIds[wallet] > 0;
    }

    /**
     * @notice Create a proposal for time-delayed execution
     * @dev Anyone can create a proposal - the timelock delay provides the security
     * @param id The policy ID
     * @param account The account address
     * @param callData The calldata for the future operation
     * @param nonce The nonce for the future operation
     */
    function createProposal(bytes32 id, address account, bytes calldata callData, uint256 nonce) external {
        TimelockConfig storage config = timelockConfig[id][account];
        if (!config.initialized) revert IModule.NotInitialized(account);

        // Calculate proposal timing
        uint48 validAfter = uint48(block.timestamp) + config.delay;
        uint48 validUntil = validAfter + config.expirationPeriod;

        // Create userOp key for storage lookup
        bytes32 userOpKey = keccak256(abi.encode(account, keccak256(callData), nonce));

        // Check proposal doesn't already exist
        if (proposals[userOpKey][id][account].status != ProposalStatus.None) {
            revert ProposalAlreadyExists();
        }

        // Create proposal (stored by userOpKey)
        proposals[userOpKey][id][account] =
            Proposal({status: ProposalStatus.Pending, validAfter: validAfter, validUntil: validUntil});

        emit ProposalCreated(account, id, userOpKey, validAfter, validUntil);
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
        TimelockConfig storage config = timelockConfig[id][msg.sender];
        if (!config.initialized) return 1;

        // Check if this is a proposal creation request
        // Criteria: calldata is a no-op AND signature has proposal data (length >= 65)
        if (_isNoOpCalldata(userOp.callData) && userOp.signature.length >= 65) {
            // This is a proposal creation request
            return _handleProposalCreation(id, userOp, config);
        }

        // Otherwise, this is a proposal execution request
        return _handleProposalExecution(id, userOp);
    }

    /**
     * @notice Handle proposal creation from userOp
     * @dev Signature format: [callDataLength(32)][callData][nonce(32)][remaining sig data]
     */
    function _handleProposalCreation(bytes32 id, PackedUserOperation calldata userOp, TimelockConfig storage config)
        internal
        returns (uint256)
    {
        // Decode proposal data from signature
        // Format: [callDataLength(32 bytes)][callData][nonce(32 bytes)][...]
        uint256 callDataLength = uint256(bytes32(userOp.signature[0:32]));

        // Validate signature has enough data
        if (userOp.signature.length < 64 + callDataLength) return 1;

        bytes calldata proposalCallData = userOp.signature[32:32 + callDataLength];
        uint256 proposalNonce = uint256(bytes32(userOp.signature[32 + callDataLength:64 + callDataLength]));

        // Calculate proposal timing
        uint48 validAfter = uint48(block.timestamp) + config.delay;
        uint48 validUntil = validAfter + config.expirationPeriod;

        // Create userOp key for storage lookup (using PROPOSAL calldata and nonce, not current userOp)
        bytes32 userOpKey = keccak256(abi.encode(userOp.sender, keccak256(proposalCallData), proposalNonce));

        // Check proposal doesn't already exist
        if (proposals[userOpKey][id][msg.sender].status != ProposalStatus.None) {
            return 1; // Proposal already exists
        }

        // Create proposal
        proposals[userOpKey][id][msg.sender] =
            Proposal({status: ProposalStatus.Pending, validAfter: validAfter, validUntil: validUntil});

        emit ProposalCreated(msg.sender, id, userOpKey, validAfter, validUntil);

        // Return failure to prevent execution (this was just proposal creation)
        return 1;
    }

    /**
     * @notice Handle proposal execution from userOp
     */
    function _handleProposalExecution(bytes32 id, PackedUserOperation calldata userOp) internal returns (uint256) {
        // Create userOp key to look up the proposal
        bytes32 userOpKey = keccak256(abi.encode(userOp.sender, keccak256(userOp.callData), userOp.nonce));

        Proposal storage proposal = proposals[userOpKey][id][msg.sender];

        // Check proposal exists and is pending
        if (proposal.status != ProposalStatus.Pending) return 1;

        // Mark as executed
        proposal.status = ProposalStatus.Executed;

        emit ProposalExecuted(msg.sender, id, userOpKey);

        // Return validAfter and validUntil for EntryPoint to validate timing
        return _packValidationData(proposal.validAfter, proposal.validUntil);
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
        // Need: 4 (selector) + 32 (mode) + 32 (offset) + 32 (length) + data
        if (callData.length < 68) return false;

        // Decode the offset to executionCalldata (should be 32)
        uint256 offset = uint256(bytes32(callData[36:68]));
        if (offset != 32) return false;

        // Decode the length of executionCalldata
        if (callData.length < 100) return false;
        uint256 execDataLength = uint256(bytes32(callData[68:100]));

        // For single execution mode, executionCalldata format is:
        // target (20 bytes) + value (32 bytes) + calldata (variable)
        if (execDataLength < 52) return false;

        // Extract target address (first 20 bytes of executionCalldata)
        address target = address(bytes20(callData[100:120]));

        // Check if target is self or address(0)
        if (target != msg.sender && target != address(0)) return false;

        // Extract value (next 32 bytes)
        uint256 value = uint256(bytes32(callData[120:152]));

        // Value must be 0
        if (value != 0) return false;

        // Check calldata length (remaining bytes should indicate empty calldata)
        // executionCalldata = target(20) + value(32) + calldataLength(32) + calldata
        if (callData.length < 184) {
            // If we don't have enough for calldata length field, it's malformed
            return false;
        }

        uint256 innerCalldataLength = uint256(bytes32(callData[152:184]));

        // Inner calldata must be empty
        return innerCalldataLength == 0;
    }

    /**
     * @notice Check if executeUserOp call is a no-op
     * @dev Valid: executeUserOp("", bytes32)
     */
    function _isNoOpExecuteUserOp(bytes calldata callData) internal view returns (bool) {
        // executeUserOp(bytes calldata userOp, bytes32 userOpHash)
        // Format: 4 (selector) + 32 (userOp offset) + 32 (userOpHash) + 32 (userOp length) + userOp data
        if (callData.length < 100) return false;

        // Decode offset to userOp data (should be 32)
        uint256 offset = uint256(bytes32(callData[4:36]));
        if (offset != 32) return false;

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
     * @param id The policy ID
     * @return validationData 0 if valid, 1 if invalid
     */
    function checkSignaturePolicy(bytes32 id, address, bytes32, bytes calldata)
        external
        view
        override
        returns (uint256)
    {
        TimelockConfig storage config = timelockConfig[id][msg.sender];
        if (!config.initialized) return 1;

        // For signature validation, we're more permissive
        // Timelock is primarily for userOp execution
        return 0;
    }

    /**
     * @notice Get proposal details
     * @param account The account address
     * @param callData The calldata
     * @param nonce The nonce
     * @param id The policy ID
     * @param wallet The wallet address
     * @return status The proposal status
     * @return validAfter When the proposal becomes valid
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
    function computeUserOpKey(address account, bytes calldata callData, uint256 nonce)
        external
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(account, keccak256(callData), nonce));
    }
}
