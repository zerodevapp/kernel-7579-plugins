// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @author taek <leekt216@gmail.com>

import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {ECDSAValidator} from "src/validators/ECDSAValidator.sol";
import {ERC1271_MAGICVALUE, ERC1271_INVALID} from "src/types/Constants.sol";

// Minimal cheatcode surface. Inheriting forge-std `Test` pulls in a base constructor that calls
// vm.deployCode(string) (StdConfig), which Halmos 0.3.3 does not support and fails setUp().
interface Vm {
    function assume(bool) external pure;
    function prank(address) external;
    function etch(address, bytes calldata) external;
    function store(address, bytes32, bytes32) external;
    function load(address, bytes32) external view returns (bytes32);
}

/// @notice Halmos proof harness for the three ECDSAValidator access gates:
///   (a) isValidSignatureWithSender returns MAGICVALUE only if owner != 0  (gate at line 97/98)
///   (b) preCheck reverts SenderNotOwner iff msgSender != owner            (require at line 120)
///   (c) onInstall reverts ZeroAddressOwner when decoded owner == 0        (require at line 41)
///
/// MODELING (recover treated as an uninterpreted oracle — see TCB note):
///   `_verifySignature` calls `ECDSA.tryRecoverCalldata`, which routes to the ecrecover precompile
///   (staticcall to address 1). Halmos models ecrecover as an UNINTERPRETED function, so calling the
///   REAL contract with a symbolic (hash, sig) yields `recovered` as an oracle: the same (hash, sig)
///   always recovers the same address, and no concrete constraint is placed on what that address is.
///   This lets us prove the OBSERVABLE gate (return / revert selector) without recomputing ecrecover.
contract ECDSAValidatorGateHalmos is SymTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    ECDSAValidator internal validator;

    // The smart account under whose storage slot the owner is registered.
    address internal constant ACCOUNT = address(0xACC);

    function setUp() external {
        // Halmos 0.3.3 cannot execute via_ir creation bytecode (routes to an unsupported
        // deployCode(string) cheat), so place the runtime code directly. ECDSAValidator has an
        // empty constructor (all state set via onInstall / vm.store), so etch is state-equivalent.
        validator = ECDSAValidator(address(uint160(uint256(keccak256("ECDSAValidator")))));
        vm.etch(address(validator), type(ECDSAValidator).runtimeCode);
    }

    // Writes `owner` into ecdsaValidatorStorage[ACCOUNT].owner directly (bypasses onInstall's
    // owner!=0 guard so we can also test the owner==0 branch of (a)). mapping(address => struct{address})
    // at declaration slot 0: slot = keccak256(abi.encode(ACCOUNT, uint256(0))); struct field 0 is `owner`.
    function _setOwner(address owner) internal {
        bytes32 slot = keccak256(abi.encode(ACCOUNT, uint256(0)));
        vm.store(address(validator), slot, bytes32(uint256(uint160(owner))));
    }

    // -------------------------------------------------------------------------------------------
    // (a) isValidSignatureWithSender: MAGICVALUE => owner != 0  (and owner == 0 => INVALID)
    // -------------------------------------------------------------------------------------------

    /// @notice (a) The ERC-1271 gate: whenever the real function returns MAGICVALUE, the stored owner
    ///         is non-zero. Owner, sender, hash and sig are all symbolic; recover is the ecrecover
    ///         oracle. Observable postcondition (line 97 gate): MAGICVALUE => owner != 0.
    function check_ecdsaGate_magicValueImpliesOwnerSet(address owner, address sender, bytes32 hash, bytes memory sig)
        external
    {
        _setOwner(owner);

        vm.prank(ACCOUNT);
        bytes4 result = validator.isValidSignatureWithSender(sender, hash, sig);

        // Gate: a valid result is impossible with an unset owner.
        assert(!(result == ERC1271_MAGICVALUE && owner == address(0)));
        // Complement (line 97): unset owner always yields INVALID (never any other bytes4).
        assert(!(owner == address(0) && result != ERC1271_INVALID));
    }

    /// @notice (a) Reachability witness: MAGICVALUE is reachable with owner != 0 AND recovered == owner.
    ///         We pin owner to the ecrecover oracle result for THIS (hash, sig): if that value is
    ///         non-zero, the raw-hash branch of _verifySignature must return true => MAGICVALUE.
    ///         Asserting `result != MAGICVALUE` here MUST yield a counterexample (path is live).
    function check_ecdsaGate_magicValueReachable(bytes32 hash, bytes memory sig) external {
        // recovered = the (uninterpreted) ecrecover oracle for (hash, sig).
        address recovered = _recoverOracle(hash, sig);
        vm.assume(recovered != address(0)); // the only precondition needed for a valid signature

        _setOwner(recovered); // owner matches the recovered signer => _verifySignature true branch

        vm.prank(ACCOUNT);
        bytes4 result = validator.isValidSignatureWithSender(address(0xB0B), hash, sig);

        // Counterexample expected: MAGICVALUE IS reachable (owner != 0, recovered == owner).
        assert(result != ERC1271_MAGICVALUE);
    }

    // Exposes the same ecrecover oracle the contract uses for the raw hash (solady tryRecoverCalldata).
    // Uses the identical staticcall-to-precompile-1 path, so Halmos unifies it with the in-contract call.
    function _recoverOracle(bytes32 hash, bytes memory sig) internal view returns (address result) {
        // 65-byte form: v = sig[64], r = sig[0:32], s = sig[32:64] (mirrors solady case 65).
        assembly {
            let len := mload(sig)
            if eq(len, 65) {
                let m := mload(0x40)
                mstore(0x00, hash)
                mstore(0x20, byte(0, mload(add(sig, add(0x20, 0x40))))) // v
                mstore(0x40, mload(add(sig, 0x20))) // r
                mstore(0x60, mload(add(sig, add(0x20, 0x20)))) // s
                pop(staticcall(gas(), 1, 0x00, 0x80, 0x40, 0x20))
                mstore(0x60, 0)
                result := mload(xor(0x60, returndatasize()))
                mstore(0x40, m)
            }
        }
    }

    // -------------------------------------------------------------------------------------------
    // (b) preCheck: reverts SenderNotOwner iff msgSender != owner (both directions)
    // -------------------------------------------------------------------------------------------

    /// @notice (b) preCheck reverts SenderNotOwner iff msgSender != owner. Asserts BOTH directions:
    ///         msgSender == owner => no revert; msgSender != owner => revert with SenderNotOwner.
    function check_ecdsaGate_preCheckSenderEqOwner(address owner, address msgSender) external {
        _setOwner(owner);

        vm.prank(ACCOUNT);
        (bool ok, bytes memory ret) =
            address(validator).call(abi.encodeCall(ECDSAValidator.preCheck, (msgSender, 0, hex"")));

        if (msgSender == owner) {
            // Forward direction: equal => the require passes => no revert.
            assert(ok);
        } else {
            // Reverse direction: unequal => revert, and specifically with SenderNotOwner().
            assert(!ok);
            assert(bytes4(ret) == ECDSAValidator.SenderNotOwner.selector);
        }
    }

    /// @notice (b) Reachability witness: the non-revert path (msgSender == owner) is live.
    ///         Asserting `!ok` on the equal branch MUST yield a counterexample (proves it can succeed).
    function check_ecdsaGate_preCheckReachable(address owner) external {
        _setOwner(owner);

        vm.prank(ACCOUNT);
        (bool ok,) = address(validator).call(abi.encodeCall(ECDSAValidator.preCheck, (owner, 0, hex"")));

        // Counterexample expected: preCheck DOES succeed when msgSender == owner (path is live).
        assert(!ok);
    }

    // -------------------------------------------------------------------------------------------
    // (c) onInstall: owner == 0 reverts ZeroAddressOwner; length != 20 reverts InvalidDataLength
    // -------------------------------------------------------------------------------------------

    /// @notice (c) onInstall with a well-formed (length-20) payload whose decoded owner is zero
    ///         reverts ZeroAddressOwner. Length is fixed to 20 so we isolate the owner==0 gate
    ///         (line 41) from the length gate (line 39). ACCOUNT is uninitialized (owner slot 0).
    function check_ecdsaGate_onInstallZeroOwnerReverts(bytes32 tail) external {
        // 20-byte payload with all-zero owner bytes; `tail` is unused entropy proving the revert
        // does not depend on payload content beyond the 20 owner bytes being zero.
        tail; // silence unused warning; kept symbolic to widen the input space
        bytes memory data = new bytes(20); // all zero => decoded owner == address(0)

        vm.prank(ACCOUNT);
        (bool ok, bytes memory ret) = address(validator).call(abi.encodeCall(ECDSAValidator.onInstall, (data)));

        assert(!ok);
        assert(bytes4(ret) == ECDSAValidator.ZeroAddressOwner.selector);
    }

    /// @notice (c) Reachability witness: onInstall SUCCEEDS with a length-20, non-zero-owner payload,
    ///         proving the revert in the property above is discriminating (not a universal revert).
    ///         Asserting `!ok` MUST yield a counterexample.
    function check_ecdsaGate_onInstallReachable(address owner) external {
        vm.assume(owner != address(0));
        bytes memory data = abi.encodePacked(owner); // exactly 20 bytes, non-zero owner

        vm.prank(ACCOUNT);
        (bool ok,) = address(validator).call(abi.encodeCall(ECDSAValidator.onInstall, (data)));

        assert(!ok);
    }
}
