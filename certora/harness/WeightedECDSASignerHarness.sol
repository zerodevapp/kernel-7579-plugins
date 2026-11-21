// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {WeightedECDSASigner} from "src/signers/WeightedECDSASigner.sol";
import {ERC1271_MAGICVALUE, ERC1271_INVALID} from "src/types/Constants.sol";

/// @title WeightedECDSASignerHarness
/// @author taek <leekt216@gmail.com>
/// @notice Certora harness for the SIGNER's installed ERC-1271 path AFTER the EC-01 refactor moved
///         the aggregation logic onto the shared WeightedThresholdBase. This harness DERIVES from the
///         real WeightedECDSASigner and drives the REAL, COMPILED base bytecode
///         (WeightedThresholdBase._verifySorted, src/base/WeightedThresholdBase.sol:38-93) exactly as
///         reached through WeightedECDSASigner.checkSignature (src/signers/WeightedECDSASigner.sol
///         :162-170) -> _verifySorted -> _guardianWeight (id-keyed guardian[signer][cfg][account],
///         :122-129).
///
///         RE-ANCHORING (WECDSA-THRESHOLD-01): the pre-refactor spec summarized an in-signer
///         `_validateSignature` that no longer exists and reimplemented the loop byte-for-byte. That
///         copy could silently drift from the moved code. This harness removes the copy — the loop,
///         ascending gate, check-before-count ordering and threshold `>=` all run as the real base
///         bytecode. Only ECDSA recovery is abstracted.
///
///         RECOVER SUMMARY: ECDSA.tryRecoverCalldata is inline assembly the SMT engine cannot invert.
///         The spec (certora/WeightedECDSASigner.spec) summarizes it as an UNINTERPRETED, DETERMINISTIC
///         ghost `recoveredSigner(i)` keyed on the RECOVERY CALL INDEX i. _verifySorted recovers slice
///         0 first (loop i=0), then the last slice, in strict program order, so call index == slice
///         index for the small slice counts these rules exercise (1 and 2): call#0 -> slice 0,
///         call#1 -> slice 1. Same slice -> same call index -> same address; a duplicate slice
///         recovers the SAME address, and the spec's `s0 == s1` precondition forces that collision
///         (the TOB-17 PoC). Identical `recoveredSigner(i)` semantics to the pre-refactor spec, now
///         re-anchored onto the moved base bytecode.
///
///         Storage weights/threshold are read through `weightOf`/`threshold` accessors bound to the
///         FIXED `ID` and to `msg.sender` (the account _verifySorted uses); the Prover leaves that
///         storage symbolic, so the adversary chooses guardian weights. Proof covers aggregation/
///         ordering, NOT ECDSA soundness.
contract WeightedECDSASignerHarness is WeightedECDSASigner {
    bytes32 public constant ID = bytes32(uint256(0x1234)); // fixed permission id / cfg
    bytes32 public constant HASH = bytes32(uint256(0x5678)); // fixed digest fed to _verifySorted

    /// @notice Real installed threshold for (ID, msg.sender), as read by checkSignature :168.
    function threshold() external view returns (uint24) {
        return weightedStorage[ID][msg.sender].threshold;
    }

    /// @notice Real id-keyed guardian weight for `signer` at (ID, msg.sender), as read by
    ///         _guardianWeight (:122-129) inside the real _verifySorted.
    function weightOf(address signer) external view returns (uint24) {
        return guardian[signer][ID][msg.sender].weight;
    }

    /// @notice Drives the REAL base _verifySorted over `sig`, returning the same bytes4
    ///         checkSignature would (:169). sigCount = sig.length / 65; `sig` content is irrelevant
    ///         (recovery is summarized by call index), so the rule pins sig.length to fix the slice
    ///         count. `sig` is calldata because _verifySorted slices it as calldata.
    function validateSignature(bytes calldata sig) external view returns (bytes4) {
        uint256 t = weightedStorage[ID][msg.sender].threshold;
        return _verifySorted(ID, msg.sender, HASH, sig, t) ? ERC1271_MAGICVALUE : ERC1271_INVALID;
    }
}
