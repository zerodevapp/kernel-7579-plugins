// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @author taek <leekt216@gmail.com>

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

/// @notice isValidSignatureWithSender returns ERC1271_MAGICVALUE only when the
///         summed weight of DISTINCT guardians reaches threshold; a duplicated single-guardian
///         signature must NOT reach threshold.
///
/// MODELING (recover treated as an uninterpreted function — see TCB note):
///   ECDSA.recover is a precompile Halmos cannot solve symbolically, so this harness makes the
///   RECOVERED SIGNER the symbolic variable. The loop over data[i*65:(i+1)*65] is replaced by a
///   loop over N symbolic signer addresses s_0..s_{n-1}. Per-signer guardian weight is looked up
///   through a real mapping keyed by the symbolic address, so the SAME address always yields the
///   SAME symbolic weight (the constraint that makes the duplicate-signer case faithful). The body
///   replicates WeightedECDSAValidator.isValidSignatureWithSender lines 296-319 VERBATIM:
///     - line 305: prevSigner = address(uint160(type(uint160).max))
///     - line 310: if (signer >= prevSigner) return ERC1271_INVALID;   (strictly-descending guard)
///     - line 313: prevSigner = signer
///     - line 314: totalWeight += guardian[signer].weight               (uint256 accumulation)
///     - line 315: if (totalWeight >= threshold) return ERC1271_MAGICVALUE;
contract WeightedECDSAAcceptSetHalmos is SymTest, Test {
    bytes4 constant ERC1271_MAGICVALUE = 0x1626ba7e;
    bytes4 constant ERC1271_INVALID = 0xffffffff;

    // Consistent per-address symbolic weight: identical signer address -> identical weight (uint24).
    mapping(address => uint24) internal weightOf;

    uint256 constant N = 3; // bounded loop (sigCount): 3 covers duplicate-adjacency + non-adjacent cases

    /// @dev Faithful replica of the accept loop. `signers` are the (uninterpreted) recover results,
    ///      `count` is data.length/65, `threshold` is strg.threshold. Returns the bytes4 the real
    ///      function returns AND `counted` = number of signers processed toward totalWeight before
    ///      returning (== accepting index + 1 on MAGICVALUE; only these signers are "counted").
    function _run(address[N] memory signers, uint256 count, uint24 threshold)
        internal
        view
        returns (bytes4 result, uint256 counted)
    {
        if (threshold == 0) return (ERC1271_INVALID, 0); // line 296-298
        if (count == 0) return (ERC1271_INVALID, 0); // line 300-303

        uint256 totalWeight = 0;
        address prevSigner = address(uint160(type(uint160).max)); // line 305
        for (uint256 i = 0; i < count; i++) {
            address signer = signers[i]; // line 307: recover, uninterpreted
            if (signer >= prevSigner) {
                return (ERC1271_INVALID, i); // line 310-312
            }
            prevSigner = signer; // line 313
            totalWeight += weightOf[signer]; // line 314
            if (totalWeight >= threshold) {
                return (ERC1271_MAGICVALUE, i + 1); // line 315-317: signers[0..i] counted
            }
        }
        return (ERC1271_INVALID, count); // line 319
    }

    /// @notice Any MAGICVALUE acceptance counts only pairwise-DISTINCT signers — a
    ///         duplicated address can never contribute weight twice.
    function check_MagicValueImpliesDistinctSigners(
        address s0,
        address s1,
        address s2,
        uint256 count,
        uint24 threshold,
        uint24 w0,
        uint24 w1,
        uint24 w2
    ) external {
        // sigCount = data.length/65 with N symbolic chunks modeled -> count in [1, N].
        vm.assume(count >= 1 && count <= N);

        weightOf[s0] = w0;
        weightOf[s1] = w1;
        weightOf[s2] = w2;

        address[N] memory signers = [s0, s1, s2];

        (bytes4 result, uint256 counted) = _run(signers, count, threshold);

        // POSTCONDITION (observable): if accepted, every pair among the COUNTED signers (indices
        // 0..counted-1) is distinct. Asserted only over the processed prefix, not the whole array,
        // so signers past the accepting index (never guarded, never counted) are unconstrained.
        // This does not recompute the running total; distinctness is the invariant the line-310
        // ordering guard establishes and is what blocks the duplicate-weight bug class.
        if (result == ERC1271_MAGICVALUE) {
            if (counted >= 2 && s0 == s1) assert(false); // s0,s1 both counted -> must differ
            if (counted >= 3) {
                assert(s0 != s2);
                assert(s1 != s2);
            }
        }
    }

    /// @notice VACUITY / REACHABILITY (i): the accept path is LIVE — a legitimate 2-distinct-guardian
    ///         input DOES return MAGICVALUE. Asserts false on that path; a counterexample proves the
    ///         MAGICVALUE branch of the main property is reachable (non-vacuous accept).
    function check_MagicValueImpliesDistinctSigners_reachable(
        address s0,
        address s1,
        uint256 count,
        uint24 threshold,
        uint24 w0,
        uint24 w1
    ) external {
        vm.assume(count >= 1 && count <= N);
        weightOf[s0] = w0;
        weightOf[s1] = w1;
        weightOf[address(0)] = 0; // s2 slot unused in this witness

        address[N] memory signers = [s0, s1, address(0)];
        (bytes4 result,) = _run(signers, count, threshold);

        // If Halmos can drive this to MAGICVALUE, the accept path is reachable -> expect a CEX here.
        assert(result != ERC1271_MAGICVALUE);
    }

    /// @notice REACHABILITY (ii) — a bounded proof: with ONE guardian of weight w
    ///         where 2w >= threshold > w, a DUPLICATED signature (s0 == s1) can NEVER reach threshold;
    ///         the line-310 ordering guard rejects the second (equal) signer BEFORE it is counted, so
    ///         the result is always ERC1271_INVALID. This proves the guard discriminates duplicates.
    function check_DuplicateSignerRejected(address s, uint24 w, uint24 threshold) external {
        // Single-guardian weight-doubling preconditions (genuine impossibilities only):
        vm.assume(threshold != 0);
        vm.assume(w < threshold); // one signature alone is below threshold
        vm.assume(uint256(w) * 2 >= threshold); // ...but counting it twice would reach it

        weightOf[s] = w; // the single guardian
        // Duplicate the SAME signer across both slots (s0 == s1 == s); recover determinism guarantees
        // identical calldata chunks recover to the identical address, which this models directly.
        address[N] memory signers = [s, s, s];

        (bytes4 result,) = _run(signers, 2, threshold);

        // The duplicate must be rejected: never MAGICVALUE.
        assertEq(result, ERC1271_INVALID);
    }
}
