// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {TimelockPolicy} from "src/policies/TimelockPolicy.sol";

/// @notice Certora harness for TimelockPolicy's proposal state machine (TL-LIFECYCLE-01).
///
/// The real execution/creation paths reconstruct the storage key from a
/// PackedUserOperation (keccak256(abi.encode(sender, keccak256(callData), nonce))) and
/// slice proposal fields out of the signature calldata — neither is tractable to drive
/// symbolically from CVL. This harness surfaces the SAME real transition logic keyed by an
/// explicit (account, callData, nonce) triple, so the spec can fix one triple across
/// execute / cancel / read and — under optimistic_hashing (injective keccak) — land on the
/// same storage slot every time.
///
/// It does NOT reimplement the state machine: execUserOp builds a PackedUserOperation and
/// calls the real internal `_handleProposalExecutionInternal`; cancelProposal is the real
/// external function; statusOf reads the real `proposals` mapping. `plantProposal` and
/// `initConfig` only set pre-state (the "symbolic status over {None,Pending,Executed,
/// Cancelled}" universe and an initialized config) — pre-state, not transition logic.
/// @author taek <leekt216@gmail.com>
contract TimelockPolicyHarness is TimelockPolicy {
    /// @notice Raw status of the proposal at the (account, callData, nonce) slot for (id, wallet).
    /// Reads the real `proposals` mapping via the SAME key the transition functions compute.
    function statusOf(bytes32 id, address wallet, address account, bytes calldata callData, uint256 nonce)
        external
        view
        returns (uint8)
    {
        bytes32 userOpKey = keccak256(abi.encode(account, keccak256(callData), nonce));
        return uint8(proposals[userOpKey][id][wallet].status);
    }

    /// @notice epoch of the proposal at the slot (for the epoch-match gate in execution).
    function epochOf(bytes32 id, address wallet, address account, bytes calldata callData, uint256 nonce)
        external
        view
        returns (uint256)
    {
        bytes32 userOpKey = keccak256(abi.encode(account, keccak256(callData), nonce));
        return proposals[userOpKey][id][wallet].epoch;
    }

    /// @notice Drive the REAL execution transition for a proposal keyed by the given userOp.
    /// Calls the real internal `_handleProposalExecutionInternal` directly with a calldata
    /// PackedUserOperation — no memory->calldata self-hop — so the whole path inlines for the
    /// Prover (keeps the sanity/vacuity engine able to see a live non-reverting path). The spec
    /// constrains userOp.sender/callData/nonce to match the planted proposal's key.
    /// Returns the ERC-4337 validation data (SIG_VALIDATION_FAILED_UINT == 1 on failure).
    function execUserOp(bytes32 id, PackedUserOperation calldata userOp, address account) external returns (uint256) {
        return _handleProposalExecutionInternal(id, userOp, account);
    }

    // ---- pre-state setters (set the symbolic starting universe; NOT transition logic) ----

    /// @notice Initialize config so the policy treats (id, wallet) as installed and gives a
    /// current epoch. Sets currentEpoch to `epoch` so plantProposal can match/mismatch it.
    function initConfig(
        bytes32 id,
        address wallet,
        uint48 delay,
        uint48 expirationPeriod,
        address guardian,
        uint256 epoch
    ) external {
        timelockConfig[id][wallet] = TimelockConfig({
            delay: delay, expirationPeriod: expirationPeriod, guardian: guardian, initialized: true
        });
        currentEpoch[id][wallet] = epoch;
    }

    /// @notice Plant an arbitrary proposal pre-state at the (account, callData, nonce) slot.
    /// Lets the spec quantify status over {None, Pending, Executed, Cancelled}.
    function plantProposal(
        bytes32 id,
        address wallet,
        address account,
        bytes calldata callData,
        uint256 nonce,
        uint8 status,
        uint48 validAfter,
        uint48 validUntil,
        uint256 epoch
    ) external {
        bytes32 userOpKey = keccak256(abi.encode(account, keccak256(callData), nonce));
        proposals[userOpKey][id][wallet] =
            Proposal({status: ProposalStatus(status), validAfter: validAfter, validUntil: validUntil, epoch: epoch});
    }

    // Status ordinals (ProposalStatus enum) and the SIG_VALIDATION_FAILED sentinel (1) are
    // expressed as CVL `definition`s in the spec — no harness constant getters needed.
}
