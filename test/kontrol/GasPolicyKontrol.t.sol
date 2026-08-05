// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @author taek <leekt216@gmail.com>
///
/// Kontrol (KEVM) proof: GasPolicy.checkUserOpPolicy cannot under-charge
/// the budget via uint128 truncation. KEVM confirms the EVM-level MUL + downcast
/// semantics on the exact 2^128 boundary — the value Kontrol adds over Halmos is
/// bytecode-level grounding of the truncation boundary.
///
/// NOTE (dispatch blocker): this project has no Kontrol config (no kontrol.toml,
/// no kontrol-cheatcodes dependency, no KontrolTest base). Initializing Kontrol is
/// a structural change requiring team-lead approval, so this spec is authored but
/// NOT built/proven this dispatch. Once `kontrol init` + kontrol-cheatcodes are
/// added, run:
///   kontrol build
///   kontrol prove --match-test 'GasPolicyKontrol.prove_gasPolicy_noUnderCharge'
///   kontrol prove --match-test 'GasPolicyKontrol.prove_gasPolicy_boundaryRejected'
///   kontrol prove --match-test 'GasPolicyKontrol.prove_gasPolicy_successReachable'
///   kontrol prove --match-test 'GasPolicyKontrol.prove_gasPolicy_paymasterShortDataNoRevert'

import {Test} from "forge-std/Test.sol";
import {KontrolCheats} from "kontrol-cheatcodes/KontrolCheats.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {GasPolicy} from "src/policies/GasPolicy.sol";

contract GasPolicyKontrol is Test, KontrolCheats {
    GasPolicy internal policy;

    uint256 constant SUCCESS = 0; // SIG_VALIDATION_SUCCESS_UINT
    uint256 constant FAILED = 1; // SIG_VALIDATION_FAILED_UINT

    function setUp() public {
        policy = new GasPolicy();
    }

    // --------------------------------------------------------------------------
    // Helper: build a PackedUserOperation with symbolic gas fields.
    // verificationGasLimit / callGasLimit / maxFeePerGas are the uint128 slices of
    // accountGasLimits (hi/lo) and gasFees (lo). preVerificationGas is full uint256
    // but bounded so the TRUE product is representable in uint256 (no ~2^320 wrap).
    // --------------------------------------------------------------------------
    function _buildOp(uint256 preVG, uint128 vgl, uint128 cgl, uint128 mfpg)
        internal
        pure
        returns (PackedUserOperation memory op)
    {
        op.accountGasLimits = bytes32((uint256(vgl) << 128) | uint256(cgl));
        op.preVerificationGas = preVG;
        // gasFees = maxPriorityFeePerGas(hi) || maxFeePerGas(lo); only lo is read.
        op.gasFees = bytes32(uint256(mfpg));
        // empty dynamic fields
    }

    // Install a Live config with a symbolic allowed budget, no paymaster enforcement.
    function _installLive(bytes32 id, uint128 allowed) internal {
        vm.prank(address(this));
        bytes memory data = abi.encode(allowed, false, address(0));
        policy.onInstall(abi.encodePacked(id, data));
    }

    // ==========================================================================
    // Main property: no under-charge. On SUCCESS the budget decreases by the TRUE
    // (uint256-computed) cost; monotone non-increasing always.
    // Reference trueCost is computed independently in uint256 here — NOT read back
    // from the contract (that would be a tautological recompute of line 40).
    // ==========================================================================
    function prove_gasPolicy_noUnderCharge(
        bytes32 id,
        uint256 preVG,
        uint128 vgl,
        uint128 cgl,
        uint128 mfpg,
        uint128 allowedPre
    ) public {
        // Bound preVG so the sum fits well under uint256 and the product cannot wrap.
        // sum <= 2^130, mfpg <= 2^128 => product <= 2^258 < 2^256? No — bound tighter:
        // require sum * mfpg < 2^256 by bounding operands.
        vm.assume(preVG <= type(uint96).max); // sum < 2^97
        // vgl, cgl are uint128 -> sum of three < 2^129; but with preVG<=2^96 sum<2^130.
        // To guarantee product representable, bound mfpg so sum*mfpg < 2^256.
        // sum < 2^130, so require mfpg < 2^126 => product < 2^256.
        vm.assume(mfpg < (uint128(1) << 126));

        _installLive(id, allowedPre);
        PackedUserOperation memory op = _buildOp(preVG, vgl, cgl, mfpg);

        // Independent reference cost in full uint256 (does not touch the contract).
        uint256 trueCost = (preVG + uint256(vgl) + uint256(cgl)) * uint256(mfpg);

        vm.prank(address(this));
        uint256 ret = policy.checkUserOpPolicy(id, op);

        (uint128 allowedPost,,) = policy.gasPolicyConfig(id, address(this));

        if (ret == SUCCESS) {
            // (a) true cost within budget AND budget decreased by exactly trueCost.
            assert(trueCost <= uint256(allowedPre));
            assert(uint256(allowedPost) == uint256(allowedPre) - trueCost);
        }
        // (c) monotone non-increasing always.
        assert(uint256(allowedPost) <= uint256(allowedPre));
    }

    // ==========================================================================
    // Reachability witness for the truncation boundary:
    // vgl = 2^80, mfpg = 2^48 => product == 2^128 exactly, low128 == 0. A uint128
    // truncation would pass this huge cost as 0; the contract MUST reject it
    // whenever allowedPre < 2^128. KEVM checks the MUL + downcast at the exact bit.
    // ==========================================================================
    function prove_gasPolicy_boundaryRejected(bytes32 id, uint128 allowedPre) public {
        vgl_boundary_helper(id, allowedPre);
    }

    function vgl_boundary_helper(bytes32 id, uint128 allowedPre) internal {
        // allowedPre is uint128 => strictly < 2^128 == trueCost, so must be rejected.
        _installLive(id, allowedPre);

        uint128 vgl = uint128(1) << 80; // 2^80
        uint128 mfpg = uint128(1) << 48; // 2^48
        // trueCost = 2^80 * 2^48 = 2^128 (preVG=cgl=0)
        PackedUserOperation memory op = _buildOp(0, vgl, 0, mfpg);

        uint256 trueCost = (uint256(vgl) + 0 + 0) * uint256(mfpg);
        // trueCost == 2^128 > any uint128 allowedPre.
        assert(trueCost > uint256(allowedPre));

        vm.prank(address(this));
        uint256 ret = policy.checkUserOpPolicy(id, op);

        (uint128 allowedPost,,) = policy.gasPolicyConfig(id, address(this));

        // (b) over-cap op MUST NOT return SUCCESS; budget untouched.
        assert(ret == FAILED);
        assert(allowedPost == allowedPre);
    }

    // ==========================================================================
    // Reachability witness that SUCCESS is reachable (non-vacuity): concrete
    // assignment with trueCost <= allowed. If this reverts / is infeasible the
    // main proof would be vacuous.
    // ==========================================================================
    function prove_gasPolicy_successReachable(bytes32 id) public {
        _installLive(id, 1000);
        PackedUserOperation memory op = _buildOp(10, 20, 30, 5); // cost = 60*5 = 300

        vm.prank(address(this));
        uint256 ret = policy.checkUserOpPolicy(id, op);
        (uint128 allowedPost,,) = policy.gasPolicyConfig(id, address(this));

        assert(ret == SUCCESS);
        assert(allowedPost == 700); // 1000 - 300
    }

    // ==========================================================================
    // With enforcePaymaster=true, allowedPaymaster != 0, and
    // paymasterAndData.length < 20, the function returns FAILED and does NOT
    // revert on the [0:20] slice (line 46 guard short-circuits before the slice).
    // ==========================================================================
    function prove_gasPolicy_paymasterShortDataNoRevert(bytes32 id, address pm) public {
        vm.assume(pm != address(0));

        vm.prank(address(this));
        policy.onInstall(abi.encodePacked(id, abi.encode(uint128(type(uint128).max), true, pm)));

        PackedUserOperation memory op = _buildOp(1, 1, 1, 1);
        op.paymasterAndData = hex"1122334455"; // length 5 < 20

        vm.prank(address(this));
        uint256 ret = policy.checkUserOpPolicy(id, op);

        assert(ret == FAILED);
    }
}
