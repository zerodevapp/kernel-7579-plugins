// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {WeightedThresholdBase} from "src/base/WeightedThresholdBase.sol";

/// @title WeightedUserOpDedupHarness
/// @author taek <leekt216@gmail.com>
/// @notice Certora harness for the split-UserOp weighted-threshold path
///         WeightedThresholdBase._verifyUserOp (src/base/WeightedThresholdBase.sol:102-176).
///
///         RACE / certora leg (EC-02-USEROP-DEDUP): this harness INHERITS the real
///         WeightedThresholdBase and calls its REAL _verifyUserOp bytecode. Nothing about the
///         aggregation / ordering / de-dup loop is re-implemented here (unlike the Halmos
///         verbatim replica). The only thing summarized away is ECDSA.tryRecoverCalldata,
///         which is an ecrecover-precompile the symbolic engine cannot invert; the CVL spec
///         replaces `ECDSA.tryRecoverCalldata(hash, slice)` with a deterministic ghost keyed on
///         the message `hash`. Because the N-1 proposal signatures are recovered against
///         `proposalHash` and the final signature against `finalHash`, the proposal-signer and
///         the final-signer recover to INDEPENDENT symbolic addresses -- and the adversary is
///         free to choose the final signer EQUAL to the (single) proposal signer, which is
///         exactly the double-count attack this proof must refute.
///
///         DISCLOSED TCB: proof covers the real base aggregation/ordering/de-dup logic, NOT
///         ECDSA soundness. Real base bytecode makes this leg TCB-independent from the Halmos
///         replica leg.
contract WeightedUserOpDedupHarness is WeightedThresholdBase {
    // Real guardian-weight mapping keyed by recovered signer address.
    mapping(address => uint256) public weightOf;

    error ZeroWeightSigner();
    error SignersNotSorted();

    function _revertZeroWeightSigner() internal pure override {
        revert ZeroWeightSigner();
    }

    function _revertSignersNotSorted() internal pure override {
        revert SignersNotSorted();
    }

    // ponytail: args named (cfg, account) purely to silence Certora's via_ir "unnamed argument"
    // summary warning; only `signer` is used.

    /// @dev Weight lookup delegated to the real mapping; cfg/account are ignored in the harness
    ///      (single guardian set) -- the aggregation logic under test does not depend on them.
    function _guardianWeight(bytes32 cfg, address account, address signer) internal view override returns (uint256) {
        cfg;
        account;
        return weightOf[signer];
    }

    /// @notice Thin external wrapper over the REAL WeightedThresholdBase._verifyUserOp.
    ///         `sig` is real calldata, so the base's %65 / sigCount / slice-offset arithmetic and
    ///         its proposal loop + final-slice pass + de-dup scan all execute on real bytecode.
    function verifyUserOp(bytes32 proposalHash, bytes32 finalHash, bytes calldata sig, uint256 threshold)
        external
        view
        returns (bool)
    {
        return _verifyUserOp(bytes32(0), address(0), proposalHash, finalHash, sig, threshold);
    }
}
