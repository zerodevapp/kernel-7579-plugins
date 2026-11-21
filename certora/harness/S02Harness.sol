// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {TimelockPolicy} from "src/policies/TimelockPolicy.sol";

/// @notice Certora harness for the TOB-2 stale-proposal-across-reinstall property (S-02).
///
/// Unlike TimelockPolicyHarness (which PLANTS an arbitrary proposal.epoch to test the
/// epoch-gate in isolation), this harness drives the REAL epoch state machine end to end so
/// the proof witnesses the genuine trace: install (epoch bump) -> create (stamps currentEpoch)
/// -> reinstall (epoch bump) -> execute (must FAIL because the stamped epoch is now stale).
///
/// It does NOT reimplement any transition:
///   - reinstall() calls the REAL onInstall (PolicyBase) which runs _policyOninstall and its
///     `currentEpoch[id][msg.sender]++`, the exact line under audit (:113).
///   - createProposal() stamps the proposal epoch with the REAL `currentEpoch[id][account]`
///     expression the production creation path uses (:227-232), on the fixed triple.
///   - execUserOp() calls the REAL _handleProposalExecutionInternal (:243), including the
///     epoch gate at :256.
///   - statusOf/epochOf/currentEpoch are observable reads of the real `proposals`/`currentEpoch`.
///
/// The (account, callData, nonce) triple is fixed across create/execute/read so, under
/// optimistic_hashing (injective keccak), every operation lands on the same storage slot.
/// @author taek <leekt216@gmail.com>
contract S02Harness is TimelockPolicy {
    /// @notice Drive the REAL install epoch bump for (id, wallet = the caller).
    /// Calls the real internal `_policyOninstall` directly so `msg.sender` is the account that
    /// invoked `install` (NOT the harness — that was the S02Harness v1 bug). In production the
    /// ERC-7579 account itself calls the module's onInstall, so keying `currentEpoch` by
    /// msg.sender is exactly the production semantics; here msg.sender == the installing account.
    /// This runs the unmodified init guard + `currentEpoch[id][msg.sender]++`. First-ever install
    /// goes 0 -> 1; a reinstall requires a prior uninstall. `config` is the abi.encode of
    /// (delay, expirationPeriod, guardian) so `_policyOninstall`'s abi.decode succeeds.
    function install(bytes32 id, bytes calldata config) external {
        _policyOninstall(id, config);
    }

    /// @notice Drive the REAL uninstall for (id, wallet = the caller).
    function uninstall(bytes32 id, bytes calldata data) external {
        _policyOnUninstall(id, data);
    }

    /// @notice Create a Pending proposal at the fixed (account, callData, nonce) slot, stamping
    /// the REAL current epoch (identical expression to the production creation path). Kept as a
    /// thin wrapper so the spec can drive creation on a symbolic triple; the epoch value written
    /// is not chosen by the spec — it is read live from `currentEpoch[id][account]`.
    function createProposal(
        bytes32 id,
        address account,
        bytes calldata callData,
        uint256 nonce,
        uint48 validAfter,
        uint48 validUntil
    ) external {
        bytes32 userOpKey = keccak256(abi.encode(account, keccak256(callData), nonce));
        require(proposals[userOpKey][id][account].status == ProposalStatus.None, "exists");
        proposals[userOpKey][id][account] = Proposal({
            status: ProposalStatus.Pending,
            validAfter: validAfter,
            validUntil: validUntil,
            epoch: currentEpoch[id][account]
        });
    }

    /// @notice Drive the REAL execution transition on the fixed triple.
    function execUserOp(bytes32 id, address account, bytes calldata callData, uint256 nonce)
        external
        returns (uint256)
    {
        PackedUserOperation memory userOp;
        userOp.sender = account;
        userOp.nonce = nonce;
        userOp.callData = callData;
        return this._execCalldata(id, userOp, account);
    }

    function _execCalldata(bytes32 id, PackedUserOperation calldata userOp, address account)
        external
        returns (uint256)
    {
        require(msg.sender == address(this));
        return _handleProposalExecutionInternal(id, userOp, account);
    }

    // ---- observable reads ----
    function statusOf(bytes32 id, address wallet, address account, bytes calldata callData, uint256 nonce)
        external
        view
        returns (uint8)
    {
        bytes32 userOpKey = keccak256(abi.encode(account, keccak256(callData), nonce));
        return uint8(proposals[userOpKey][id][wallet].status);
    }

    function epochOf(bytes32 id, address wallet, address account, bytes calldata callData, uint256 nonce)
        external
        view
        returns (uint256)
    {
        bytes32 userOpKey = keccak256(abi.encode(account, keccak256(callData), nonce));
        return proposals[userOpKey][id][wallet].epoch;
    }

    function currentEpochOf(bytes32 id, address wallet) external view returns (uint256) {
        return currentEpoch[id][wallet];
    }

    function isInitialized(bytes32 id, address wallet) external view returns (bool) {
        return timelockConfig[id][wallet].initialized;
    }

    function ST_PENDING() external pure returns (uint8) {
        return uint8(ProposalStatus.Pending);
    }

    function sigFailedSentinel() external pure returns (uint256) {
        return 1;
    }
}
