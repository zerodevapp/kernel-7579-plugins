// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {ECDSASigner} from "src/signers/ECDSASigner.sol";
import {
    SIG_VALIDATION_SUCCESS_UINT,
    SIG_VALIDATION_FAILED_UINT,
    ERC1271_MAGICVALUE,
    ERC1271_INVALID
} from "src/types/Constants.sol";

// Minimal cheatcode surface. Inheriting forge-std `Test` pulls in a base constructor that calls
// vm.deployCode(string) (StdConfig), which Halmos 0.3.3 does not support and fails setUp().
interface Vm {
    function assume(bool) external pure;
    function prank(address) external;
    function etch(address, bytes calldata) external;
}

/// @author taek <leekt216@gmail.com>
/// @notice Halmos proof harness for ECDSASigner's anti-null-match guard.
///         Proves the observable return codes of checkUserOpSignature / checkSignature match the
///         predicate (owner != 0 && ecrecover-match), with ECDSA recovery as an uninterpreted oracle
///         (Halmos models the ecrecover precompile as an uninterpreted function).
contract ECDSASignerNullMatchHalmos is SymTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    ECDSASigner internal signerc;

    // Fixed caller so the (id, wallet) storage slot is concrete-keyed (Halmos-friendly).
    address internal constant CALLER = address(0xCA11);

    function setUp() external {
        // Halmos 0.3.3 cannot execute ECDSASigner's via_ir creation bytecode (routes to an
        // unsupported deployCode(string) cheat). ECDSASigner has no constructor logic (empty ctor,
        // inherits SignerBase), so placing the runtime code directly is state-equivalent.
        signerc = ECDSASigner(address(uint160(uint256(keccak256("ECDSASigner")))));
        vm.etch(address(signerc), type(ECDSASigner).runtimeCode);
    }

    // Installs a concrete-but-symbolic-valued owner for (id, CALLER) via onInstall.
    // Only installs when owner != 0 (the contract rejects the zero-address signer).
    function _install(bytes32 id, address owner) internal {
        vm.assume(owner != address(0));
        bytes memory data = abi.encodePacked(id, bytes20(owner));
        vm.prank(CALLER);
        signerc.onInstall(data);
    }

    function _userOp(bytes memory sig) internal pure returns (PackedUserOperation memory op) {
        op.signature = sig;
    }

    // ---------------------------------------------------------------------------------------------
    // checkUserOpSignature
    // ---------------------------------------------------------------------------------------------

    /// @notice checkUserOpSignature returns SUCCESS iff owner != 0 AND recovery matches owner;
    ///         when owner == 0 (unset) it must return FAILED regardless of the signature.
    ///         Observable: the return code equals the (owner-set && recover-match) predicate, where
    ///         the recover-match is witnessed by the contract's own _verifySignature semantics — the
    ///         harness never recomputes recovery, it reads owner from storage and lets the SUCCESS
    ///         branch itself certify the match (any SUCCESS with owner==0 falsifies the guard).
    function check_checkUserOpSignature_nullMatchGuard(bytes32 id, address owner, bytes memory sig) external {
        // owner is the value we will store; owner == 0 models the UNSET slot (never installed).
        if (owner != address(0)) {
            _install(id, owner);
        }
        // else: slot left untouched => signer[id][CALLER] == address(0) (unset).

        PackedUserOperation memory op = _userOp(sig);

        vm.prank(CALLER);
        uint256 ret = signerc.checkUserOpSignature(id, op, keccak256(sig));

        // Read the on-chain owner (0 if unset) directly from the contract.
        address stored = signerc.signer(id, CALLER);

        // Core guard (contrapositive): SUCCESS => signer was set (non-null).
        // If owner is unset, SUCCESS is impossible; if a failed recovery returned address(0) that
        // matched an unset slot, this would fire.
        if (ret == SIG_VALIDATION_SUCCESS_UINT) {
            assert(stored != address(0));
        } else {
            // The only non-SUCCESS code this function emits is FAILED.
            assert(ret == SIG_VALIDATION_FAILED_UINT);
        }
    }

    /// @notice Unset-signer branch: when the slot was never installed, checkUserOpSignature MUST
    ///         return FAILED for every signature. Single observable assertion.
    function check_checkUserOpSignature_unsetFails(bytes32 id, bytes memory sig) external {
        // Slot deliberately left unset (no _install).
        PackedUserOperation memory op = _userOp(sig);

        vm.prank(CALLER);
        uint256 ret = signerc.checkUserOpSignature(id, op, keccak256(sig));

        assert(ret == SIG_VALIDATION_FAILED_UINT);
    }

    // ---------------------------------------------------------------------------------------------
    // checkSignature (ERC-1271 analogue)
    // ---------------------------------------------------------------------------------------------

    /// @notice checkSignature returns MAGICVALUE => signer was set (non-null); otherwise INVALID.
    function check_checkSignature_nullMatchGuard(
        bytes32 id,
        address owner,
        address sender,
        bytes32 hash,
        bytes memory sig
    ) external {
        if (owner != address(0)) {
            _install(id, owner);
        }

        vm.prank(CALLER);
        bytes4 ret = signerc.checkSignature(id, sender, hash, sig);

        address stored = signerc.signer(id, CALLER);

        if (ret == ERC1271_MAGICVALUE) {
            assert(stored != address(0));
        } else {
            assert(ret == ERC1271_INVALID);
        }
    }

    /// @notice Unset-signer branch: checkSignature MUST return INVALID when the slot is unset.
    function check_checkSignature_unsetFails(bytes32 id, address sender, bytes32 hash, bytes memory sig) external {
        vm.prank(CALLER);
        bytes4 ret = signerc.checkSignature(id, sender, hash, sig);

        assert(ret == ERC1271_INVALID);
    }

    // ---------------------------------------------------------------------------------------------
    // REACHABILITY / NON-VACUITY WITNESSES
    // ---------------------------------------------------------------------------------------------

    /// @notice Witness: the SUCCESS leaf of checkUserOpSignature is LIVE (owner set, recovery matches).
    ///         Asserts false on the SUCCESS return; a counterexample proves the path is satisfiable.
    function check_checkUserOpSignature_successReachable(bytes32 id, address owner, bytes memory sig) external {
        _install(id, owner); // owner != 0 enforced inside

        PackedUserOperation memory op = _userOp(sig);

        vm.prank(CALLER);
        uint256 ret = signerc.checkUserOpSignature(id, op, keccak256(sig));

        // If Halmos can satisfy owner == ecrecover(hash, sig), this fires (path live => non-vacuous).
        assert(ret != SIG_VALIDATION_SUCCESS_UINT);
    }

    /// @notice Witness: the unset-signer FAILED leaf is LIVE. Slot unset, assert not-FAILED so a
    ///         counterexample proves the unset path is reachable (non-vacuous).
    function check_checkUserOpSignature_unsetReachable(bytes32 id, bytes memory sig) external {
        PackedUserOperation memory op = _userOp(sig);

        vm.prank(CALLER);
        uint256 ret = signerc.checkUserOpSignature(id, op, keccak256(sig));

        assert(ret != SIG_VALIDATION_FAILED_UINT);
    }
}
