// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {WebAuthnValidator, WebAuthnValidatorData} from "src/validators/WebAuthnValidator.sol";
import {WebAuthnSigner, WebAuthnSignerData} from "src/signers/WebAuthnSigner.sol";
import {P256 as WebAuthnP256} from "solady/utils/P256.sol";
import {SIG_VALIDATION_SUCCESS_UINT, SIG_VALIDATION_FAILED_UINT} from "src/types/Constants.sol";

interface Vm {
    function assume(bool) external pure;
    function prank(address) external;
    function etch(address, bytes calldata) external;
    function store(address, bytes32, bytes32) external;
}

contract WebAuthnP256PrecompileHalmosStub {
    fallback() external {
        assembly ("memory-safe") {
            mstore(0, sload(0))
            return(0, 0x20)
        }
    }
}

/// @notice Exposes Solady's production P256 low-s gate without the surrounding module ABI.
contract WebAuthnPrimitiveHalmosHarness {
    function verifyP256(bytes32 hash, uint256 r, uint256 s, uint256 x, uint256 y) external view returns (bool) {
        return WebAuthnP256.verifySignature(hash, bytes32(r), bytes32(s), bytes32(x), bytes32(y));
    }
}

/// @notice Production validator with only the cryptographic/parser boundary replaced by a
///         deterministic argument-checking oracle. The real stateless data-length, ABI-decode,
///         zero-key, and dispatch logic remains inherited byte-for-byte.
contract WebAuthnValidatorOracleHarness is WebAuthnValidator {
    bytes32 internal constant ORACLE_ENABLED_SLOT = keccak256("WebAuthnHalmos.oracle.enabled");
    bytes32 internal constant ORACLE_HASH_SLOT = keccak256("WebAuthnHalmos.oracle.hash");
    bytes32 internal constant ORACLE_X_SLOT = keccak256("WebAuthnHalmos.oracle.x");
    bytes32 internal constant ORACLE_Y_SLOT = keccak256("WebAuthnHalmos.oracle.y");
    bytes32 internal constant ORACLE_SIGNATURE_LENGTH_SLOT = keccak256("WebAuthnHalmos.oracle.signatureLength");

    function _verifySignature(bytes32 hash, bytes calldata signature, WebAuthnValidatorData memory data)
        internal
        view
        override
        returns (uint256)
    {
        bytes32 enabledSlot = ORACLE_ENABLED_SLOT;
        bytes32 hashSlot = ORACLE_HASH_SLOT;
        bytes32 xSlot = ORACLE_X_SLOT;
        bytes32 ySlot = ORACLE_Y_SLOT;
        bytes32 signatureLengthSlot = ORACLE_SIGNATURE_LENGTH_SLOT;
        uint256 enabled;
        bytes32 expectedHash;
        uint256 expectedX;
        uint256 expectedY;
        uint256 expectedSignatureLength;
        assembly ("memory-safe") {
            enabled := sload(enabledSlot)
            expectedHash := sload(hashSlot)
            expectedX := sload(xSlot)
            expectedY := sload(ySlot)
            expectedSignatureLength := sload(signatureLengthSlot)
        }

        bool matches = hash == expectedHash && data.pubKeyX == expectedX && data.pubKeyY == expectedY
            && signature.length == expectedSignatureLength;
        return enabled != 0 && matches ? SIG_VALIDATION_SUCCESS_UINT : SIG_VALIDATION_FAILED_UINT;
    }
}

/// @notice Production signer with the same deterministic argument-checking verification oracle.
contract WebAuthnSignerOracleHarness is WebAuthnSigner {
    bytes32 internal constant ORACLE_ENABLED_SLOT = keccak256("WebAuthnHalmos.oracle.enabled");
    bytes32 internal constant ORACLE_HASH_SLOT = keccak256("WebAuthnHalmos.oracle.hash");
    bytes32 internal constant ORACLE_X_SLOT = keccak256("WebAuthnHalmos.oracle.x");
    bytes32 internal constant ORACLE_Y_SLOT = keccak256("WebAuthnHalmos.oracle.y");
    bytes32 internal constant ORACLE_SIGNATURE_LENGTH_SLOT = keccak256("WebAuthnHalmos.oracle.signatureLength");

    function _verifySignature(bytes32 hash, bytes calldata signature, WebAuthnSignerData memory data)
        internal
        view
        override
        returns (uint256)
    {
        bytes32 enabledSlot = ORACLE_ENABLED_SLOT;
        bytes32 hashSlot = ORACLE_HASH_SLOT;
        bytes32 xSlot = ORACLE_X_SLOT;
        bytes32 ySlot = ORACLE_Y_SLOT;
        bytes32 signatureLengthSlot = ORACLE_SIGNATURE_LENGTH_SLOT;
        uint256 enabled;
        bytes32 expectedHash;
        uint256 expectedX;
        uint256 expectedY;
        uint256 expectedSignatureLength;
        assembly ("memory-safe") {
            enabled := sload(enabledSlot)
            expectedHash := sload(hashSlot)
            expectedX := sload(xSlot)
            expectedY := sload(ySlot)
            expectedSignatureLength := sload(signatureLengthSlot)
        }

        bool matches = hash == expectedHash && data.pubKeyX == expectedX && data.pubKeyY == expectedY
            && signature.length == expectedSignatureLength;
        return enabled != 0 && matches ? SIG_VALIDATION_SUCCESS_UINT : SIG_VALIDATION_FAILED_UINT;
    }
}

/// @author taek <leekt216@gmail.com>
/// @notice Halmos proofs for stateless WebAuthn module dispatch and Solady's locally decidable P256
///         low-s gate.
///
///         TCB / MODELING: the production stateless config gates and module dispatch execute from
///         inherited bytecode. `_verifySignature` is a deterministic oracle that also checks the
///         forwarded hash, public-key coordinates, and signature length. Solady's P256 low-s gate
///         is proven separately through WebAuthnPrimitiveHalmosHarness.
///
///         COVERAGE GAP: Halmos 0.3.3 cannot execute the full Base64URL + multiple SHA-256 pipeline
///         with symbolic challenges (symbolic lookup indices and mixed-width SHA UFs). Challenge,
///         response-type, and authenticator-data integration remain covered by concrete Forge tests
///         and Solady's upstream suite; elliptic-curve soundness remains in the native verifier TCB.
contract WebAuthnStatelessHalmos is SymTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    address internal constant PRECOMPILE = address(0x100);
    address internal constant CALLER = address(0xCA11);
    bytes32 internal constant ID = bytes32(uint256(0x1234));
    bytes32 internal constant ORACLE_ENABLED_SLOT = keccak256("WebAuthnHalmos.oracle.enabled");
    bytes32 internal constant ORACLE_HASH_SLOT = keccak256("WebAuthnHalmos.oracle.hash");
    bytes32 internal constant ORACLE_X_SLOT = keccak256("WebAuthnHalmos.oracle.x");
    bytes32 internal constant ORACLE_Y_SLOT = keccak256("WebAuthnHalmos.oracle.y");
    bytes32 internal constant ORACLE_SIGNATURE_LENGTH_SLOT = keccak256("WebAuthnHalmos.oracle.signatureLength");
    uint256 internal constant P256_N_DIV_2 =
        57896044605178124381348723474703786764998477612067880171211129530534256022184;

    WebAuthnValidatorOracleHarness internal validator;
    WebAuthnSignerOracleHarness internal signer;
    WebAuthnPrimitiveHalmosHarness internal primitives;

    function setUp() external {
        WebAuthnP256PrecompileHalmosStub stub =
            WebAuthnP256PrecompileHalmosStub(address(uint160(uint256(keccak256("WebAuthnP256PrecompileHalmosStub")))));
        vm.etch(address(stub), type(WebAuthnP256PrecompileHalmosStub).runtimeCode);
        vm.etch(PRECOMPILE, address(stub).code);

        validator =
            WebAuthnValidatorOracleHarness(address(uint160(uint256(keccak256("WebAuthnValidatorOracleHarness")))));
        vm.etch(address(validator), type(WebAuthnValidatorOracleHarness).runtimeCode);

        signer = WebAuthnSignerOracleHarness(address(uint160(uint256(keccak256("WebAuthnSignerOracleHarness")))));
        vm.etch(address(signer), type(WebAuthnSignerOracleHarness).runtimeCode);

        primitives =
            WebAuthnPrimitiveHalmosHarness(address(uint160(uint256(keccak256("WebAuthnPrimitiveHalmosHarness")))));
        vm.etch(address(primitives), type(WebAuthnPrimitiveHalmosHarness).runtimeCode);
    }

    function _data(uint256 x, uint256 y) internal pure returns (bytes memory) {
        return abi.encode(WebAuthnValidatorData(x, y), bytes32(0));
    }

    function _signerInstallData(uint256 x, uint256 y) internal pure returns (bytes memory) {
        return abi.encodePacked(ID, abi.encode(WebAuthnSignerData(x, y), bytes32(0)));
    }

    function _armOracle(bytes32 hash, uint256 x, uint256 y, uint256 signatureLength, bool enabled) internal {
        address[2] memory targets = [address(validator), address(signer)];
        for (uint256 i; i < targets.length; i++) {
            vm.store(targets[i], ORACLE_ENABLED_SLOT, bytes32(uint256(enabled ? 1 : 0)));
            vm.store(targets[i], ORACLE_HASH_SLOT, hash);
            vm.store(targets[i], ORACLE_X_SLOT, bytes32(x));
            vm.store(targets[i], ORACLE_Y_SLOT, bytes32(y));
            vm.store(targets[i], ORACLE_SIGNATURE_LENGTH_SLOT, bytes32(signatureLength));
        }
    }

    function _setP256Oracle(bool result) internal {
        vm.store(PRECOMPILE, bytes32(0), bytes32(uint256(result ? 1 : 0)));
    }

    // =============================================================================================
    // STATELESS CONFIG / DISPATCH
    // =============================================================================================

    function check_StatelessOraclePlumbing(
        bytes32 hash,
        uint256 x,
        uint256 y,
        bool oracleResult,
        address requestingProtocol
    ) external {
        vm.assume(x != 0 && y != 0);
        bytes memory signature = hex"010203";
        _armOracle(hash, x, y, signature.length, oracleResult);

        bool validatorDirect = validator.validateSignatureWithData(hash, signature, _data(x, y));
        bool validatorWithSender =
            validator.validateSignatureWithDataWithSender(requestingProtocol, hash, signature, _data(x, y));
        bool signerDirect = signer.validateSignatureWithData(hash, signature, _data(x, y));
        bool signerWithSender =
            signer.validateSignatureWithDataWithSender(requestingProtocol, hash, signature, _data(x, y));

        assert(validatorDirect == oracleResult);
        assert(validatorWithSender == oracleResult);
        assert(signerDirect == oracleResult);
        assert(signerWithSender == oracleResult);
    }

    function check_StatelessConfigurationGuards(bytes32 hash) external {
        _armOracle(hash, 1, 1, 0, true);

        assert(!validator.validateSignatureWithData(hash, hex"", hex"01"));
        assert(!signer.validateSignatureWithData(hash, hex"", hex"01"));
        assert(!validator.validateSignatureWithData(hash, hex"", _data(0, 1)));
        assert(!signer.validateSignatureWithData(hash, hex"", _data(1, 0)));
    }

    function check_StatelessIgnoresInstalledState(bytes32 hash, uint256 x, uint256 y, bool oracleResult) external {
        vm.assume(x != 0 && y != 0);
        bytes memory signature = hex"010203";
        _armOracle(hash, x, y, signature.length, oracleResult);

        bool validatorBefore = validator.validateSignatureWithData(hash, signature, _data(x, y));
        bool signerBefore = signer.validateSignatureWithData(hash, signature, _data(x, y));

        vm.prank(CALLER);
        validator.onInstall(_data(7, 11));
        vm.prank(CALLER);
        signer.onInstall(_signerInstallData(7, 11));

        bool validatorAfter = validator.validateSignatureWithData(hash, signature, _data(x, y));
        bool signerAfter = signer.validateSignatureWithData(hash, signature, _data(x, y));

        assert(validatorBefore == validatorAfter);
        assert(signerBefore == signerAfter);
        assert(validatorAfter == signerAfter);
    }

    // =============================================================================================
    // SOLADY P256 PRIMITIVE
    // =============================================================================================

    function check_P256LowSOracleExact(bytes32 hash, uint256 r, uint256 s, uint256 x, uint256 y, bool oracleResult)
        external
    {
        vm.assume(s <= P256_N_DIV_2);
        _setP256Oracle(oracleResult);
        assert(primitives.verifyP256(hash, r, s, x, y) == oracleResult);
    }

    function check_P256HighSAlwaysRejects(bytes32 hash, uint256 r, uint256 x, uint256 y, uint256 excess) external {
        vm.assume(excess <= type(uint256).max - P256_N_DIV_2 - 1);
        _setP256Oracle(true);
        assert(!primitives.verifyP256(hash, r, P256_N_DIV_2 + 1 + excess, x, y));
    }

    // =============================================================================================
    // NON-VACUITY WITNESSES (counterexamples expected)
    // =============================================================================================

    function check_StatelessAcceptReachable(bytes32 hash) external {
        bytes memory signature = hex"010203";
        _armOracle(hash, 1, 1, signature.length, true);
        bool result = validator.validateSignatureWithData(hash, signature, _data(1, 1));
        assert(!result);
    }

    function check_StatelessRejectReachable(bytes32 hash) external {
        bytes memory signature = hex"010203";
        _armOracle(hash, 1, 1, signature.length, false);
        bool result = signer.validateSignatureWithData(hash, signature, _data(1, 1));
        assert(result);
    }
}
