// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {WebAuthnValidator, WebAuthnValidatorData} from "src/validators/WebAuthnValidator.sol";
import {WebAuthnSigner, WebAuthnSignerData} from "src/signers/WebAuthnSigner.sol";
import {SIG_VALIDATION_SUCCESS_UINT, SIG_VALIDATION_FAILED_UINT} from "src/types/Constants.sol";

// Minimal cheatcode surface. Inheriting forge-std `Test` pulls in a base constructor that calls
// vm.deployCode(string) (StdConfig), which Halmos 0.3.3 does not support and fails setUp().
// Note: expectRevert(bytes4) is NOT supported by Halmos 0.3.3, so revert checks use low-level
// .call and inspect the returned revert selector directly.
interface Vm {
    function assume(bool) external pure;
    function prank(address) external;
    function etch(address, bytes calldata) external;
}

/// @author taek <leekt216@gmail.com>
/// @notice Halmos proof harness for WebAuthnValidator / WebAuthnSigner storage-key correctness
///         and install/uninstall lifecycle guards. The WebAuthn/P256 signature verification is
///         NOT proved here: Solady WebAuthn verification is an INTERNAL library that inlines Base64URL
///         encoding, sha256, JSON offset checks, and P256 verification over an unbounded
///         (bytes,string,...) abi.decode of the signature — intractable for Halmos and reported
///         OUT-OF-SCOPE (claims (a)/(b) SUCCESS-tracking). This harness proves the observable
///         lifecycle behaviour that does not decode the signature:
///           (c) onInstall rejects pubKeyX==0 || pubKeyY==0 (InvalidPublicKey),
///               reverts AlreadyInitialized on double-install;
///               onUninstall reverts NotInitialized when unset;
///               WebAuthnSigner increments/decrements usedIds without underflow;
///           per-key storage separation: a stored key lands under the correct (account) /
///               (id,account) key and is readable back, and unset keys read as zero.
contract WebAuthnKeyLifecycleHalmos is SymTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    WebAuthnValidator internal validator;
    WebAuthnSigner internal signer;

    // Fixed caller so the (account)/(id,account) storage slots are concrete-keyed (Halmos-friendly).
    address internal constant CALLER = address(0xCA11);
    address internal constant OTHER = address(0xB0B);

    // AlreadyInitialized(address) / NotInitialized(address) live on IERC7579Modules.
    bytes4 internal constant ALREADY_INIT = bytes4(keccak256("AlreadyInitialized(address)"));
    bytes4 internal constant NOT_INIT = bytes4(keccak256("NotInitialized(address)"));
    bytes4 internal constant INVALID_PUBKEY = bytes4(keccak256("InvalidPublicKey()"));

    function setUp() external {
        // Halmos 0.3.3 cannot execute the via_ir creation bytecode (routes to an unsupported
        // deployCode(string) cheat). Neither contract has constructor logic (WebAuthnValidator has
        // no constructor; WebAuthnSigner inherits SignerBase's empty ctor), so placing runtime code
        // directly is state-equivalent.
        validator = WebAuthnValidator(address(uint160(uint256(keccak256("WebAuthnValidator")))));
        vm.etch(address(validator), type(WebAuthnValidator).runtimeCode);

        signer = WebAuthnSigner(address(uint160(uint256(keccak256("WebAuthnSigner")))));
        vm.etch(address(signer), type(WebAuthnSigner).runtimeCode);
    }

    // install payload for the validator: abi.encode(WebAuthnValidatorData, bytes32)
    function _valData(uint256 x, uint256 y) internal pure returns (bytes memory) {
        return abi.encode(WebAuthnValidatorData({pubKeyX: x, pubKeyY: y}), bytes32(0));
    }

    // install payload for the signer: id (32 bytes) || abi.encode(WebAuthnSignerData, bytes32)
    function _sigData(bytes32 id, uint256 x, uint256 y) internal pure returns (bytes memory) {
        return abi.encodePacked(id, abi.encode(WebAuthnSignerData({pubKeyX: x, pubKeyY: y}), bytes32(0)));
    }

    // Extracts the leading 4-byte selector from returndata (0 if none).
    function _selector(bytes memory ret) internal pure returns (bytes4 s) {
        if (ret.length >= 4) {
            assembly {
                s := mload(add(ret, 0x20))
            }
        }
    }

    // =============================================================================================
    // (c) VALIDATOR LIFECYCLE
    // =============================================================================================

    /// @notice onInstall reverts InvalidPublicKey iff either coordinate is zero; otherwise it stores
    ///         the (x,y) under webAuthnValidatorStorage[msg.sender] and marks the account initialized.
    ///         Observable: revert-selector / stored-value, no signature decode.
    function check_Validator_onInstall_pubkeyGuardAndStore(uint256 x, uint256 y) external {
        vm.prank(CALLER);
        (bool ok, bytes memory ret) = address(validator).call(abi.encodeCall(validator.onInstall, (_valData(x, y))));
        if (x == 0 || y == 0) {
            assert(!ok && _selector(ret) == INVALID_PUBKEY);
        } else {
            assert(ok);
            (uint256 sx, uint256 sy) = validator.webAuthnValidatorStorage(CALLER);
            // stored under the CORRECT key, exactly the installed value.
            assert(sx == x && sy == y);
            assert(validator.isInitialized(CALLER));
        }
    }

    /// @notice Double-install reverts AlreadyInitialized.
    function check_Validator_onInstall_doubleReverts(uint256 x, uint256 y) external {
        vm.assume(x != 0 && y != 0);
        vm.prank(CALLER);
        validator.onInstall(_valData(x, y));

        vm.prank(CALLER);
        (bool ok, bytes memory ret) = address(validator).call(abi.encodeCall(validator.onInstall, (_valData(x, y))));
        assert(!ok && _selector(ret) == ALREADY_INIT);
    }

    /// @notice onUninstall reverts NotInitialized when the account was never installed.
    function check_Validator_onUninstall_unsetReverts() external {
        vm.prank(CALLER);
        (bool ok, bytes memory ret) = address(validator).call(abi.encodeCall(validator.onUninstall, ("")));
        assert(!ok && _selector(ret) == NOT_INIT);
    }

    /// @notice After uninstall the key is cleared and the account reads as uninitialized.
    function check_Validator_onUninstall_clears(uint256 x, uint256 y) external {
        vm.assume(x != 0 && y != 0);
        vm.prank(CALLER);
        validator.onInstall(_valData(x, y));

        vm.prank(CALLER);
        validator.onUninstall("");

        (uint256 sx, uint256 sy) = validator.webAuthnValidatorStorage(CALLER);
        assert(sx == 0 && sy == 0);
        assert(!validator.isInitialized(CALLER));
    }

    /// @notice Per-account key separation: installing for CALLER never populates OTHER's slot.
    function check_Validator_keySeparation(uint256 x, uint256 y) external {
        vm.assume(x != 0 && y != 0);
        vm.prank(CALLER);
        validator.onInstall(_valData(x, y));

        (uint256 ox, uint256 oy) = validator.webAuthnValidatorStorage(OTHER);
        assert(ox == 0 && oy == 0);
        assert(!validator.isInitialized(OTHER));
    }

    // =============================================================================================
    // (c) SIGNER LIFECYCLE
    // =============================================================================================

    /// @notice _signerOninstall reverts InvalidPublicKey iff either coordinate is zero; otherwise it
    ///         stores under webAuthnSignerStorage[id][msg.sender] and increments usedIds[msg.sender].
    function check_Signer_onInstall_pubkeyGuardAndStore(bytes32 id, uint256 x, uint256 y) external {
        vm.prank(CALLER);
        (bool ok, bytes memory ret) = address(signer).call(abi.encodeCall(signer.onInstall, (_sigData(id, x, y))));
        if (x == 0 || y == 0) {
            assert(!ok && _selector(ret) == INVALID_PUBKEY);
        } else {
            assert(ok);
            (uint256 sx, uint256 sy) = signer.webAuthnSignerStorage(id, CALLER);
            assert(sx == x && sy == y);
            assert(signer.usedIds(CALLER) == 1);
        }
    }

    /// @notice Double-install of the same (id) reverts AlreadyInitialized.
    function check_Signer_onInstall_doubleReverts(bytes32 id, uint256 x, uint256 y) external {
        vm.assume(x != 0 && y != 0);
        vm.prank(CALLER);
        signer.onInstall(_sigData(id, x, y));

        vm.prank(CALLER);
        (bool ok, bytes memory ret) = address(signer).call(abi.encodeCall(signer.onInstall, (_sigData(id, x, y))));
        assert(!ok && _selector(ret) == ALREADY_INIT);
    }

    /// @notice onUninstall reverts NotInitialized when (id, msg.sender) was never installed.
    function check_Signer_onUninstall_unsetReverts(bytes32 id) external {
        bytes memory data = abi.encodePacked(id, bytes(""));
        vm.prank(CALLER);
        (bool ok, bytes memory ret) = address(signer).call(abi.encodeCall(signer.onUninstall, (data)));
        assert(!ok && _selector(ret) == NOT_INIT);
    }

    /// @notice Uninstall clears the (id,account) key and decrements usedIds without underflow:
    ///         install then uninstall returns usedIds to 0 (no wrap to 2**256-1).
    function check_Signer_onUninstall_clearsAndDecrements(bytes32 id, uint256 x, uint256 y) external {
        vm.assume(x != 0 && y != 0);
        vm.prank(CALLER);
        signer.onInstall(_sigData(id, x, y));

        vm.prank(CALLER);
        signer.onUninstall(abi.encodePacked(id, bytes("")));

        (uint256 sx, uint256 sy) = signer.webAuthnSignerStorage(id, CALLER);
        assert(sx == 0 && sy == 0);
        assert(signer.usedIds(CALLER) == 0);
    }

    /// @notice Per-(id,account) key separation: installing (id, CALLER) never populates (id, OTHER)
    ///         nor a different id for CALLER.
    function check_Signer_keySeparation(bytes32 id, bytes32 id2, uint256 x, uint256 y) external {
        vm.assume(x != 0 && y != 0);
        vm.assume(id != id2);
        vm.prank(CALLER);
        signer.onInstall(_sigData(id, x, y));

        // different account, same id
        (uint256 ox, uint256 oy) = signer.webAuthnSignerStorage(id, OTHER);
        assert(ox == 0 && oy == 0);
        // same account, different id
        (uint256 dx, uint256 dy) = signer.webAuthnSignerStorage(id2, CALLER);
        assert(dx == 0 && dy == 0);
    }

    // =============================================================================================
    // REACHABILITY / NON-VACUITY WITNESSES
    // =============================================================================================

    /// @notice Witness: the validator install SUCCESS leaf is LIVE (non-zero key stores & inits).
    function check_Validator_installReachable(uint256 x, uint256 y) external {
        vm.assume(x != 0 && y != 0);
        vm.prank(CALLER);
        validator.onInstall(_valData(x, y));
        // path live => this fires with a counterexample.
        assert(!validator.isInitialized(CALLER));
    }

    /// @notice Witness: the validator InvalidPublicKey revert leaf is LIVE. Low-level call so the
    ///         revert does not abort the test; assert the call SUCCEEDED => counterexample proves the
    ///         revert path is actually taken (non-vacuous).
    function check_Validator_invalidPubkeyReachable(uint256 y) external {
        vm.prank(CALLER);
        (bool ok, bytes memory ret) = address(validator).call(abi.encodeCall(validator.onInstall, (_valData(0, y))));
        // If the revert path is live, ok==false with the InvalidPublicKey selector; asserting the
        // opposite yields a counterexample proving reachability.
        assert(ok || _selector(ret) != INVALID_PUBKEY);
    }

    /// @notice Witness: the validator AlreadyInitialized revert leaf is LIVE.
    function check_Validator_alreadyInitReachable(uint256 x, uint256 y) external {
        vm.assume(x != 0 && y != 0);
        vm.prank(CALLER);
        validator.onInstall(_valData(x, y));
        vm.prank(CALLER);
        (bool ok, bytes memory ret) = address(validator).call(abi.encodeCall(validator.onInstall, (_valData(x, y))));
        assert(ok || _selector(ret) != ALREADY_INIT);
    }

    /// @notice Witness: the validator NotInitialized revert leaf is LIVE.
    function check_Validator_notInitReachable() external {
        vm.prank(CALLER);
        (bool ok, bytes memory ret) = address(validator).call(abi.encodeCall(validator.onUninstall, ("")));
        assert(ok || _selector(ret) != NOT_INIT);
    }

    /// @notice Witness: the signer install SUCCESS leaf is LIVE (usedIds becomes 1).
    function check_Signer_installReachable(bytes32 id, uint256 x, uint256 y) external {
        vm.assume(x != 0 && y != 0);
        vm.prank(CALLER);
        signer.onInstall(_sigData(id, x, y));
        assert(signer.usedIds(CALLER) != 1);
    }

    /// @notice Witness: the signer NotInitialized revert leaf is LIVE.
    function check_Signer_notInitReachable(bytes32 id) external {
        bytes memory data = abi.encodePacked(id, bytes(""));
        vm.prank(CALLER);
        (bool ok, bytes memory ret) = address(signer).call(abi.encodeCall(signer.onUninstall, (data)));
        assert(ok || _selector(ret) != NOT_INIT);
    }
}
