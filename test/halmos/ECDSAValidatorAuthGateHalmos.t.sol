// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {ECDSAValidator} from "src/validators/ECDSAValidator.sol";
import {SIG_VALIDATION_SUCCESS_UINT, SIG_VALIDATION_FAILED_UINT} from "src/types/Constants.sol";

/// @author taek <leekt216@gmail.com>
/// @notice Halmos proof harness for ECDSAValidator.validateUserOp authorization gating.
///         ECDSA recovery is modeled as an uninterpreted oracle (Halmos models the ecrecover
///         precompile as an uninterpreted function, deterministic per (hash, sig)). The harness
///         never recomputes recovery inside an assertion — it reads the stored owner and lets the
///         contract's own SUCCESS branch certify the recover-match.
// Minimal cheatcode surface. Inheriting forge-std `Test` pulls in a base constructor that calls
// vm.deployCode(string) (StdConfig), which Halmos 0.3.3 does not support and fails setUp().
interface Vm {
    function assume(bool) external pure;
    function prank(address) external;
    function etch(address, bytes calldata) external;
}

contract ECDSAValidatorAuthGateHalmos is SymTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    ECDSAValidator internal validator;

    // Fixed caller so the storage slot ecdsaValidatorStorage[CALLER] is concrete-keyed (Halmos-friendly).
    address internal constant CALLER = address(0xCA11);

    function setUp() external {
        // Halmos 0.3.3 cannot execute ECDSAValidator's via_ir creation bytecode (routes to an
        // unsupported deployCode(string) cheat). ECDSAValidator has an empty constructor, so placing
        // the runtime code directly is state-equivalent (sound vm.etch deploy).
        validator = ECDSAValidator(address(uint160(uint256(keccak256("ECDSAValidator")))));
        vm.etch(address(validator), type(ECDSAValidator).runtimeCode);
    }

    // Installs a symbolic-valued owner for CALLER via onInstall. onInstall rejects owner == 0.
    function _install(address owner) internal {
        vm.assume(owner != address(0));
        vm.prank(CALLER);
        validator.onInstall(abi.encodePacked(bytes20(owner)));
    }

    function _userOp(bytes memory sig) internal pure returns (PackedUserOperation memory op) {
        op.signature = sig;
    }

    // ---------------------------------------------------------------------------------------------
    // CORE PROPERTY
    // ---------------------------------------------------------------------------------------------

    /// @notice validateUserOp returns SUCCESS => owner was set (non-null); otherwise it returns
    ///         FAILED. Contrapositive of "success => (owner!=0 && recovered==owner)": the observable
    ///         SUCCESS return certifies owner!=0 (the recovered==owner half is enforced by the
    ///         contract's SUCCESS branch itself; recover stays an uninterpreted oracle, never
    ///         recomputed in the assertion). owner is symbolic (may be 0), signature is symbolic.
    function check_ValidateUserOpAuthGate(address owner, bytes memory sig) external {
        // owner == 0 models the UNSET slot (never installed); owner != 0 installs it.
        if (owner != address(0)) {
            _install(owner);
        }

        PackedUserOperation memory op = _userOp(sig);

        vm.prank(CALLER);
        uint256 ret = validator.validateUserOp(op, keccak256(sig));

        (address stored) = validator.ecdsaValidatorStorage(CALLER);

        if (ret == SIG_VALIDATION_SUCCESS_UINT) {
            // SUCCESS is impossible when owner is unset: the address(0) early-fail guard
            // prevents a failed recovery (which returns address(0)) matching an unset slot.
            assert(stored != address(0));
        } else {
            // The only non-SUCCESS code this function emits is FAILED.
            assert(ret == SIG_VALIDATION_FAILED_UINT);
        }
    }

    /// @notice owner == 0 (unset) => validateUserOp returns FAILED for every signature. This is the
    ///         anti-address(0)-match guard as a standalone observable claim.
    function check_ValidateUserOpUnsetFails(bytes memory sig) external {
        // Slot deliberately left unset (no _install).
        PackedUserOperation memory op = _userOp(sig);

        vm.prank(CALLER);
        uint256 ret = validator.validateUserOp(op, keccak256(sig));

        assert(ret == SIG_VALIDATION_FAILED_UINT);
    }

    // ---------------------------------------------------------------------------------------------
    // REACHABILITY / NON-VACUITY WITNESSES
    // ---------------------------------------------------------------------------------------------

    /// @notice Witness: the SUCCESS leaf is LIVE (owner set, uninterpreted recover matches owner).
    ///         Asserts false on the SUCCESS return; a counterexample proves the path is satisfiable
    ///         (non-vacuous). If NO counterexample, the SUCCESS path is unreachable => vacuous.
    function check_ValidateUserOpAuthGate_reachable(address owner, bytes memory sig) external {
        _install(owner); // owner != 0 enforced inside

        PackedUserOperation memory op = _userOp(sig);

        vm.prank(CALLER);
        uint256 ret = validator.validateUserOp(op, keccak256(sig));

        // If Halmos can satisfy owner == recover(hash, sig), this fires (path live => non-vacuous).
        assert(ret != SIG_VALIDATION_SUCCESS_UINT);
    }

    /// @notice Witness: the unset-owner FAILED leaf is LIVE. Slot unset, assert not-FAILED so a
    ///         counterexample proves the owner==0 fail path is reachable (non-vacuous).
    function check_ValidateUserOpUnsetFails_reachable(bytes memory sig) external {
        PackedUserOperation memory op = _userOp(sig);

        vm.prank(CALLER);
        uint256 ret = validator.validateUserOp(op, keccak256(sig));

        assert(ret != SIG_VALIDATION_FAILED_UINT);
    }
}
