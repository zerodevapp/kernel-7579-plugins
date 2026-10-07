// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ERC1271_MAGICVALUE, ERC1271_INVALID} from "src/types/Constants.sol";

/// @title WeightedECDSAHarness
/// @author taek <leekt216@gmail.com>
/// @notice Certora harness for WeightedECDSAValidator.isValidSignatureWithSender
///         (src/validators/WeightedECDSAValidator.sol:294-320).
///
///         ECDSA.recover is a precompile the symbolic engine cannot invert, so it is
///         replaced by an overridable `_recoverSigner(index)` that Certora summarizes as an
///         UNINTERPRETED function returning a fully symbolic, attacker-controlled address.
///         Consistency (same signature slice -> same signer) is preserved by keying the
///         summary on the loop index i, a 1:1 image of the fixed 65-byte slice offset
///         `data[i*65:(i+1)*65]`. An adversary who submits the same slice twice therefore
///         recovers the SAME address twice; the spec's `s0 == s1` precondition forces exactly
///         that collision, replicating the audit PoC.
///
///         Every other line is a byte-for-byte copy of the fixed implementation: the
///         line-310 strictly-descending guard runs BEFORE the line-314 accumulation and the
///         line-315/316 threshold return.
contract WeightedECDSAHarness {
    uint24 public threshold;
    // guardian weight lookup keyed by recovered signer address
    mapping(address => uint24) public weightOf;

    /// @dev Uninterpreted stand-in for ECDSA.recover(hash, data[i*65:(i+1)*65]).
    ///      Certora replaces this call with the `recoveredSigner(i)` summary declared in the
    ///      spec: a symbolic address chosen by the adversary but DETERMINISTIC in `i`
    ///      (same slice -> same signer). The body below is only a compile placeholder.
    function _recoverSigner(uint256 i) internal view virtual returns (address) {
        return address(uint160(i));
    }

    /// @notice Exact port of WeightedECDSAValidator.isValidSignatureWithSender lines 294-320.
    /// @param sigCount number of 65-byte signature slices = data.length / 65
    function isValidSignatureWithSender(uint256 sigCount) external view returns (bytes4) {
        if (threshold == 0) {
            return ERC1271_INVALID;
        }
        if (sigCount == 0) {
            return ERC1271_INVALID;
        }
        uint256 totalWeight = 0;
        address prevSigner = address(uint160(type(uint160).max));
        for (uint256 i = 0; i < sigCount; i++) {
            address signer = _recoverSigner(i);
            // Enforce strictly-descending order (rejects duplicates) BEFORE counting weight,
            // otherwise a duplicated single-guardian signature could reach the threshold.
            if (signer >= prevSigner) {
                return ERC1271_INVALID;
            }
            prevSigner = signer;
            totalWeight += weightOf[signer];
            if (totalWeight >= threshold) {
                return ERC1271_MAGICVALUE;
            }
        }
        return ERC1271_INVALID;
    }
}
