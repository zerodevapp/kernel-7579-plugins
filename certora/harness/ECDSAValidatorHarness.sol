// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ECDSA} from "solady/utils/ECDSA.sol";
import {ECDSAValidator, ECDSAValidatorStorage} from "src/validators/ECDSAValidator.sol";

/// @title ECDSAValidatorHarness
/// @author taek <leekt216@gmail.com>
/// @notice Certora harness for ECDSAValidator.validateUserOp
///         (src/validators/ECDSAValidator.sol:69-81, _verifySignature :60-67).
///
///         ECDSA.tryRecoverCalldata is elliptic-curve recovery the symbolic engine cannot
///         invert. Both recover calls inside _verifySignature are routed through the
///         overridable `_recover(hash)` below, which Certora replaces with an UNINTERPRETED
///         ghost `recovered(hash)`: a symbolic, attacker-controlled address that is
///         DETERMINISTIC in the hash (same hash -> same recovered address). The two distinct
///         hashes (userOpHash and its eth-signed variant) therefore map to two independent
///         symbolic addresses, faithfully modeling the two tryRecoverCalldata calls.
///
///         The rest of the logic (owner==0 early-fail, the OR of the two recover checks,
///         the SUCCESS/FAILED return) is inherited byte-for-byte from the real contract via
///         the overridden _verifySignature, which is a line-for-line copy of the original
///         except recover is swapped for _recover.
contract ECDSAValidatorHarness is ECDSAValidator {
    /// @dev Uninterpreted stand-in for ECDSA.tryRecoverCalldata(hash, sig).
    ///      Certora summarizes this as `recovered(hash)` (declared in the spec): a symbolic
    ///      address, attacker-controlled but DETERMINISTIC in hash. Body is a compile-only
    ///      placeholder never executed under the summary.
    function _recover(bytes32 hash) internal view virtual returns (address) {
        return address(uint160(uint256(hash)));
    }

    /// @dev Stand-in for ECDSA.toEthSignedMessageHash(hash). Certora summarizes this as the
    ///      ghost `ethSignedHash(hash)` so BOTH the harness's second recover key and the
    ///      spec's assertion key are the SAME symbolic value (injective per hash). Body is a
    ///      compile-only placeholder; the concrete keccak is never executed under the summary.
    function _ethHash(bytes32 hash) internal pure virtual returns (bytes32) {
        return ECDSA.toEthSignedMessageHash(hash);
    }

    /// @dev Line-for-line copy of ECDSAValidator._verifySignature (:60-67) with the two
    ///      ECDSA.tryRecoverCalldata(...) calls replaced by _recover(hash) and the eth-hash
    ///      derivation replaced by _ethHash(hash).
    function _verifySignatureHarness(bytes32 hash, address signer) internal view returns (bool) {
        if (signer == _recover(hash)) {
            return true;
        }
        bytes32 ethHash = _ethHash(hash);
        address recovered = _recover(ethHash);
        return signer == recovered;
    }

    /// @notice Port of validateUserOp (:69-81) reading real storage, routing recovery
    ///         through the uninterpreted _recover. `userOpHash` is passed directly (the
    ///         signature is fully captured by the uninterpreted recover, so it is elided).
    function validateUserOpHarness(bytes32 userOpHash) external view returns (uint256) {
        address owner = ecdsaValidatorStorage[msg.sender].owner;
        // Fail if owner is not set (prevents matching with failed recovery returning address(0)).
        if (owner == address(0)) return 1; // SIG_VALIDATION_FAILED_UINT
        return _verifySignatureHarness(userOpHash, owner)
            ? 0  // SIG_VALIDATION_SUCCESS_UINT
            : 1; // SIG_VALIDATION_FAILED_UINT
    }

    /// @notice Expose the owner slot for envfree reads in the spec.
    function ownerOf(address account) external view returns (address) {
        return ecdsaValidatorStorage[account].owner;
    }
}
