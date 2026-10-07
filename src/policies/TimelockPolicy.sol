// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IAccountExecute} from "account-abstraction/interfaces/IAccountExecute.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {UserOperationLib} from "account-abstraction/core/UserOperationLib.sol";
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
 *
 *      SECURITY: Signer Trust Assumption
 *      This policy trusts whichever signer module is configured on the permission.
 *      It does NOT independently verify who signed the UserOp — that responsibility
 *      belongs to the signer module (e.g., ECDSASigner, WeightedECDSASigner).
 *      The signer validates the signature; this policy only enforces the timelock.
 *
 *      SECURITY: Nonce Isolation
 *      Proposals are keyed by keccak256(account, keccak256(callData), nonce).
 *      The nonce here is the full ERC-4337 nonce (192-bit key | 64-bit sequence).
 *      Each permission has a distinct nonce key, so proposals under different
 *      permissions are naturally isolated — a proposal created under permission A
 *      cannot be executed under permission B.
 *
 *      SECURITY: Guardian Design
 *      The guardian is a CANCELLATION-ONLY role. It cannot create or execute proposals.
 *      The guardian is scoped per (policyId, wallet) — a guardian for one policy/wallet
 *      pair cannot cancel proposals belonging to another pair. Guardian is set at install
 *      time and persists until uninstall. Setting guardian to address(0) disables the
 *      guardian feature, meaning only the account itself can cancel proposals.
 */
contract TimelockPolicy is PolicyBase, IStatelessValidator, IStatelessValidatorWithSender {
    using UserOperationLib for PackedUserOperation;

    /// @dev Canonical EntryPoint v0.9 deployment used when legacy install data omits an EntryPoint.
    address public constant DEFAULT_ENTRYPOINT_V09 = 0x433709009B8330FDa32311DF1C2AFA402eD8D009;

    bytes32 private constant _EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant _ENTRYPOINT_NAME_HASH = keccak256("ERC4337");
    bytes32 private constant _ENTRYPOINT_VERSION_HASH = keccak256("1");
    bytes32 private constant _PROPOSAL_COMMITMENT_NAMESPACE =
        keccak256("kernel.7579.plugins.TimelockPolicy.proposalCommitment");

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

    // Storage: id => wallet => EntryPoint v0.9 used by that Kernel account.
    // Kept separate from TimelockConfig so the existing public getter ABI remains stable.
    mapping(bytes32 => mapping(address => address)) public configuredEntryPoint;

    // Storage: userOpKey => id => wallet => proposal
    // userOpKey = keccak256(abi.encode(account, keccak256(callData), nonce))
    mapping(bytes32 => mapping(bytes32 => mapping(address => Proposal))) public proposals;

    event ProposalCreated(
        address indexed wallet, bytes32 indexed id, bytes32 indexed proposalHash, uint256 validAfter, uint256 validUntil
    );

    event ProposalExecuted(address indexed wallet, bytes32 indexed id, bytes32 indexed proposalHash);

    event ProposalCancelled(address indexed wallet, bytes32 indexed id, bytes32 indexed proposalHash);

    event ProposalCommitted(
        address indexed wallet,
        bytes32 indexed id,
        bytes32 indexed proposalHash,
        bytes32 creationUserOpHash,
        uint256 epoch
    );

    event TimelockConfigUpdated(
        address indexed wallet, bytes32 indexed id, uint256 delay, uint256 expirationPeriod, address guardian
    );

    error InvalidDelay();
    error InvalidExpirationPeriod();
    error ProposalNotPending();
    error OnlyAccount();
    error ParametersTooLarge();
    error SignatureValidationNotSupported();
    error StatelessValidationNotSupported();
    error MissingProposalCommitment();
    error InvalidInstallData();
    error InvalidEntryPoint();
    error UnsupportedCreationInitCode();

    /**
     * @notice Install the timelock policy
     * @param _data Legacy encoding: (uint48 delay, uint48 expirationPeriod, address guardian).
     *              Extended encoding appends an EntryPoint v0.9 address.
     */
    function _policyOninstall(bytes32 id, bytes calldata _data) internal override {
        uint48 delay;
        uint48 expirationPeriod;
        address guardian;
        address entryPoint;
        if (_data.length == 96) {
            (delay, expirationPeriod, guardian) = abi.decode(_data, (uint48, uint48, address));
            entryPoint = DEFAULT_ENTRYPOINT_V09;
        } else if (_data.length == 128) {
            (delay, expirationPeriod, guardian, entryPoint) = abi.decode(_data, (uint48, uint48, address, address));
        } else {
            revert InvalidInstallData();
        }

        if (timelockConfig[id][msg.sender].initialized) {
            revert IModule.AlreadyInitialized(msg.sender);
        }

        if (delay == 0) revert InvalidDelay();
        if (expirationPeriod == 0) revert InvalidExpirationPeriod();
        if (entryPoint == address(0)) revert InvalidEntryPoint();
        if (uint256(delay) + uint256(expirationPeriod) > type(uint48).max) revert ParametersTooLarge();

        // Increment epoch to invalidate any proposals from previous installations
        currentEpoch[id][msg.sender]++;

        timelockConfig[id][msg.sender] =
            TimelockConfig({delay: delay, expirationPeriod: expirationPeriod, guardian: guardian, initialized: true});
        configuredEntryPoint[id][msg.sender] = entryPoint;

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
        delete configuredEntryPoint[id][msg.sender];
    }

    /**
     * @notice Check if this module is a specific type
     * @dev Stateless validation is deliberately not advertised: the matching functions always reject.
     */
    function isModuleType(uint256 moduleTypeId) external pure override(IModule, PolicyBase) returns (bool) {
        return moduleTypeId == MODULE_TYPE_POLICY;
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
     * @dev Called by the smart account during validation. Canonical sponsored creation calldata
     *      records a one-use commitment; all other calldata must match a pending proposal.
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
        return _validateUserOpPolicy(id, userOp, msg.sender);
    }

    /**
     * @notice Create a proposal during the execution phase of an authenticated creation UserOperation.
     * @dev The creation call is part of userOp.callData, so the permission signer authenticates every
     *      proposal field. Validation writes a one-use commitment and requires a paymaster; execution
     *      consumes it and only then reads block.timestamp to start the full delay.
     */
    function createProposal(bytes32 id, bytes calldata proposalCallData, uint256 proposalNonce) external {
        TimelockConfig storage config = timelockConfig[id][msg.sender];
        if (!config.initialized) revert IModule.NotInitialized(msg.sender);

        bytes32 userOpKey = keccak256(abi.encode(msg.sender, keccak256(proposalCallData), proposalNonce));
        uint256 epoch = currentEpoch[id][msg.sender];
        address entryPoint = configuredEntryPoint[id][msg.sender];
        if (entryPoint == address(0)) revert InvalidEntryPoint();
        bytes32 creationUserOpHash = IEntryPoint(entryPoint).getCurrentUserOpHash();
        if (
            creationUserOpHash == bytes32(0)
                || !_consumeProposalCommitment(creationUserOpHash, userOpKey, id, msg.sender, epoch)
        ) revert MissingProposalCommitment();

        Proposal storage proposal = proposals[userOpKey][id][msg.sender];
        if (proposal.status != ProposalStatus.None) revert ProposalNotPending();

        uint256 validAfter256 = block.timestamp + uint256(config.delay);
        uint256 validUntil256 = validAfter256 + uint256(config.expirationPeriod);
        if (validUntil256 > type(uint48).max) revert ParametersTooLarge();

        proposals[userOpKey][id][msg.sender] = Proposal({
            status: ProposalStatus.Pending,
            validAfter: uint48(validAfter256),
            validUntil: uint48(validUntil256),
            epoch: epoch
        });

        emit ProposalCreated(msg.sender, id, userOpKey, validAfter256, validUntil256);
    }

    /// @notice Tell DefaultSecurityHook whether a proposal-creation module call is authorized.
    /// @dev Authorization is live only while EntryPoint executes the exact UserOp that this policy
    ///      validated. The hook still requires this target and createProposal selector to be
    ///      explicitly allowlisted by the account.
    function isProposalCreationAuthorized(address account, bytes calldata createProposalCalldata)
        external
        view
        returns (bytes4 magicValue)
    {
        (bool valid, bytes32 id, bytes32 proposalCallDataHash, uint256 proposalNonce) =
            _decodeCreateProposalCall(createProposalCalldata);
        if (!valid) return bytes4(0);
        if (!timelockConfig[id][account].initialized) return bytes4(0);
        address entryPoint = configuredEntryPoint[id][account];
        if (entryPoint == address(0)) return bytes4(0);

        if (!_hasLiveProposalCommitment(account, id, proposalCallDataHash, proposalNonce, entryPoint)) {
            return bytes4(0);
        }
        return this.isProposalCreationAuthorized.selector;
    }

    function _hasLiveProposalCommitment(
        address account,
        bytes32 id,
        bytes32 proposalCallDataHash,
        uint256 proposalNonce,
        address entryPoint
    ) internal view returns (bool) {
        bytes32 creationUserOpHash;
        try IEntryPoint(entryPoint).getCurrentUserOpHash() returns (bytes32 currentHash) {
            creationUserOpHash = currentHash;
        } catch {
            return false;
        }
        if (creationUserOpHash == bytes32(0)) return false;

        bytes32 userOpKey = keccak256(abi.encode(account, proposalCallDataHash, proposalNonce));
        bytes32 slot = _proposalCommitmentSlot(creationUserOpHash, userOpKey, id, account);
        uint256 committedEpoch;
        assembly ("memory-safe") {
            committedEpoch := tload(slot)
        }
        return committedEpoch == currentEpoch[id][account];
    }

    /// @notice Canonical Kernel calldata for a sponsored proposal-creation UserOperation.
    /// @dev EntryPoint v0.9 expands the executeUserOp selector into the full account callback.
    function getProposalCreationCallData(bytes32 id, bytes calldata proposalCallData, uint256 proposalNonce)
        external
        view
        returns (bytes memory)
    {
        bytes32 mode = LibERC7579.encodeMode(
            LibERC7579.CALLTYPE_SINGLE, LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes22(0)
        );
        bytes memory inner = abi.encodeCall(this.createProposal, (id, proposalCallData, proposalNonce));
        return abi.encodePacked(
            IAccountExecute.executeUserOp.selector,
            abi.encodeWithSelector(
                IERC7579Execution.execute.selector, mode, abi.encodePacked(address(this), uint256(0), inner)
            )
        );
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
        revert SignatureValidationNotSupported();
    }

    function validateSignatureWithData(bytes32, bytes calldata, bytes calldata)
        external
        pure
        override(IStatelessValidator)
        returns (bool)
    {
        revert StatelessValidationNotSupported();
    }

    function validateSignatureWithDataWithSender(address, bytes32, bytes calldata, bytes calldata)
        external
        pure
        override(IStatelessValidatorWithSender)
        returns (bool)
    {
        revert StatelessValidationNotSupported();
    }

    // ==================== Internal Shared Logic ====================

    /**
     * @notice Internal function to validate user operation policy
     * @dev Shared validation logic for the installed policy path.
     */
    function _validateUserOpPolicy(bytes32 id, PackedUserOperation calldata userOp, address account)
        internal
        returns (uint256)
    {
        TimelockConfig storage config = timelockConfig[id][account];
        if (!config.initialized) return SIG_VALIDATION_FAILED_UINT;
        if (userOp.sender != account) return SIG_VALIDATION_FAILED_UINT;

        (bool creation, bytes32 creationId, bytes32 proposalCallDataHash, uint256 proposalNonce) =
            _decodeProposalCreation(userOp.callData);
        if (creation) {
            if (creationId != id || !_hasPaymaster(userOp.paymasterAndData)) return SIG_VALIDATION_FAILED_UINT;
            if (userOp.initCode.length != 0) return SIG_VALIDATION_FAILED_UINT;
            bytes32 userOpKey = keccak256(abi.encode(account, proposalCallDataHash, proposalNonce));
            if (proposals[userOpKey][id][account].status != ProposalStatus.None) return SIG_VALIDATION_FAILED_UINT;
            address entryPoint = configuredEntryPoint[id][account];
            if (entryPoint == address(0)) return SIG_VALIDATION_FAILED_UINT;
            bytes32 creationUserOpHash = _entryPointUserOpHash(userOp, entryPoint);
            uint256 epoch = currentEpoch[id][account];
            _storeProposalCommitment(creationUserOpHash, userOpKey, id, account, epoch);
            emit ProposalCommitted(account, id, userOpKey, creationUserOpHash, epoch);
            return _packValidationData(0, 0);
        }

        return _handleProposalExecutionInternal(id, userOp, account);
    }

    function _hasPaymaster(bytes calldata paymasterAndData) internal pure returns (bool) {
        return paymasterAndData.length >= 52 && address(bytes20(paymasterAndData[0:20])) != address(0);
    }

    /// @notice Compute the exact EntryPoint v0.9 hash used for a proposal-creation UserOperation.
    /// @dev This is computed locally because ERC-7562 forbids calling EntryPoint.getUserOpHash during validation.
    function getEntryPointUserOpHash(bytes32 id, address account, PackedUserOperation calldata userOp)
        external
        view
        returns (bytes32)
    {
        if (userOp.initCode.length != 0) revert UnsupportedCreationInitCode();
        address entryPoint = configuredEntryPoint[id][account];
        if (entryPoint == address(0)) revert InvalidEntryPoint();
        return _entryPointUserOpHash(userOp, entryPoint);
    }

    function _entryPointUserOpHash(PackedUserOperation calldata userOp, address entryPoint)
        internal
        view
        returns (bytes32)
    {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                _EIP712_DOMAIN_TYPEHASH, _ENTRYPOINT_NAME_HASH, _ENTRYPOINT_VERSION_HASH, block.chainid, entryPoint
            )
        );
        return keccak256(abi.encodePacked(hex"1901", domainSeparator, userOp.hash(bytes32(0))));
    }

    /// @notice Read a transaction-local proposal commitment.
    /// @dev The signature matches the former mapping getter to keep integrations and tests source-compatible.
    function proposalCommitments(bytes32 creationUserOpHash, bytes32 userOpKey, bytes32 id, address account)
        external
        view
        returns (uint256 epoch)
    {
        bytes32 slot = _proposalCommitmentSlot(creationUserOpHash, userOpKey, id, account);
        assembly ("memory-safe") {
            epoch := tload(slot)
        }
    }

    function _storeProposalCommitment(
        bytes32 creationUserOpHash,
        bytes32 userOpKey,
        bytes32 id,
        address account,
        uint256 epoch
    ) internal {
        bytes32 slot = _proposalCommitmentSlot(creationUserOpHash, userOpKey, id, account);
        assembly ("memory-safe") {
            tstore(slot, epoch)
        }
    }

    function _consumeProposalCommitment(
        bytes32 creationUserOpHash,
        bytes32 userOpKey,
        bytes32 id,
        address account,
        uint256 epoch
    ) internal returns (bool consumed) {
        bytes32 slot = _proposalCommitmentSlot(creationUserOpHash, userOpKey, id, account);
        uint256 storedEpoch;
        assembly ("memory-safe") {
            storedEpoch := tload(slot)
        }
        if (storedEpoch != epoch) return false;
        assembly ("memory-safe") {
            tstore(slot, 0)
        }
        return true;
    }

    /// @dev ERC-7562 recognizes an external slot as account-associated only when its outer
    ///      preimage is exactly `account || bytes32`. Hash every other discriminator into that
    ///      second word so canonical bundlers permit this shared module's transient access.
    function _proposalCommitmentSlot(bytes32 creationUserOpHash, bytes32 userOpKey, bytes32 id, address account)
        internal
        pure
        returns (bytes32)
    {
        bytes32 subkey = keccak256(abi.encode(_PROPOSAL_COMMITMENT_NAMESPACE, creationUserOpHash, userOpKey, id));
        return keccak256(abi.encode(account, subkey));
    }

    /// @dev Decode only the canonical execute(single, policy.createProposal(...)) representation.
    ///      Every offset, padded length, target and value is checked before any slice is read.
    function _decodeProposalCreation(bytes calldata callData)
        internal
        view
        returns (bool valid, bytes32 id, bytes32 proposalCallDataHash, uint256 proposalNonce)
    {
        if (callData.length < 4 || bytes4(callData[0:4]) != IAccountExecute.executeUserOp.selector) {
            return (false, 0, 0, 0);
        }
        bytes calldata accountCallData = callData[4:];
        if (accountCallData.length < 100 || bytes4(accountCallData[0:4]) != IERC7579Execution.execute.selector) {
            return (false, 0, 0, 0);
        }
        bytes32 mode = bytes32(accountCallData[4:36]);
        if (
            LibERC7579.getCallType(mode) != LibERC7579.CALLTYPE_SINGLE
                || LibERC7579.getExecType(mode) != LibERC7579.EXECTYPE_DEFAULT
                || uint256(bytes32(accountCallData[36:68])) != 64
        ) return (false, 0, 0, 0);

        uint256 executionLength = uint256(bytes32(accountCallData[68:100]));
        if (executionLength > type(uint256).max - 31) return (false, 0, 0, 0);
        uint256 paddedExecutionLength = (executionLength + 31) & ~uint256(31);
        if (paddedExecutionLength != accountCallData.length - 100 || executionLength < 184) return (false, 0, 0, 0);

        bytes calldata executionData = accountCallData[100:100 + executionLength];
        if (address(bytes20(executionData[0:20])) != address(this) || uint256(bytes32(executionData[20:52])) != 0) {
            return (false, 0, 0, 0);
        }

        return _decodeCreateProposalCall(executionData[52:]);
    }

    /// @dev Decode the one canonical createProposal(bytes32,bytes,uint256) representation used by
    ///      both UserOp validation and the hook authorization view.
    function _decodeCreateProposalCall(bytes calldata callData)
        internal
        pure
        returns (bool valid, bytes32 id, bytes32 proposalCallDataHash, uint256 proposalNonce)
    {
        if (
            callData.length < 132 || bytes4(callData[0:4]) != bytes4(keccak256("createProposal(bytes32,bytes,uint256)"))
        ) {
            return (false, 0, 0, 0);
        }
        if (uint256(bytes32(callData[36:68])) != 96) return (false, 0, 0, 0);

        id = bytes32(callData[4:36]);
        proposalNonce = uint256(bytes32(callData[68:100]));
        uint256 proposalLength = uint256(bytes32(callData[100:132]));
        if (proposalLength > type(uint256).max - 31) return (false, 0, 0, 0);
        uint256 paddedProposalLength = (proposalLength + 31) & ~uint256(31);
        if (paddedProposalLength != callData.length - 132) return (false, 0, 0, 0);
        proposalCallDataHash = keccak256(callData[132:132 + proposalLength]);
        return (true, id, proposalCallDataHash, proposalNonce);
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
