// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {P256Validator} from "src/validators/P256Validator.sol";
import {P256Signer} from "src/signers/P256Signer.sol";
import {SIG_VALIDATION_SUCCESS_UINT, SIG_VALIDATION_FAILED_UINT, ERC1271_INVALID} from "src/types/Constants.sol";

interface Vm {
    function assume(bool) external pure;
    function prank(address) external;
    function etch(address, bytes calldata) external;
    function store(address, bytes32, bytes32) external;
}

/// @notice Executable model of the RIP-7212/EIP-7951 verifier boundary.
/// @dev Slot zero is the symbolic verifier result for ordinary inputs.
contract P256PrecompileHalmosStub {
    fallback() external {
        assembly ("memory-safe") {
            let result := sload(0)
            let isProbe :=
                and(
                    and(
                        eq(calldataload(0), 0xbb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023),
                        eq(calldataload(0x20), 5)
                    ),
                    and(
                        and(
                            eq(calldataload(0x40), 1),
                            eq(calldataload(0x60), 0xa71af64de5126a4a4e02b7922d66ce9415ce88a4c9d25514d91082c8725ac957)
                        ),
                        eq(calldataload(0x80), 0x5d47723c8fbe580bb369fec9c2665d8e30a435b9932645482e7c9f11e872296b)
                    )
                )
            if isProbe { result := 1 }
            mstore(0, result)
            return(0, 0x20)
        }
    }
}

/// @author taek <leekt216@gmail.com>
/// @notice Halmos proofs for P256Validator and P256Signer lifecycle, storage scoping, and
///         stateless-dispatch correctness.
///
///         TCB / MODELING: the production module bytecode, P256Validation public-key gate, Solady
///         low-s check, and storage accesses execute unchanged. Only the native
///         verifier at address(0x100) is modeled as a deterministic boolean oracle. These properties
///         prove the module logic around the cryptographic boundary, not P-256 soundness itself.
contract P256ModuleHalmos is SymTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    address internal constant PRECOMPILE = address(0x100);
    address internal constant CALLER = address(0xCA11);
    address internal constant OTHER = address(0xB0B);
    bytes32 internal constant ID = bytes32(uint256(0x1234));
    bytes32 internal constant OTHER_ID = bytes32(uint256(0x5678));

    uint256 internal constant GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296;
    uint256 internal constant GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5;
    uint256 internal constant N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    uint256 internal constant HALF_N = N / 2;

    bytes4 internal constant ALREADY_INITIALIZED = bytes4(keccak256("AlreadyInitialized(address)"));
    bytes4 internal constant NOT_INITIALIZED = bytes4(keccak256("NotInitialized(address)"));
    bytes4 internal constant INVALID_DATA_LENGTH = bytes4(keccak256("InvalidDataLength()"));
    bytes4 internal constant INVALID_PUBLIC_KEY = bytes4(keccak256("InvalidPublicKey()"));

    P256Validator internal validator;
    P256Signer internal signer;

    function setUp() external {
        // Both production constructors only probe address(0x100). Etching runtime code after
        // installing the modeled precompile is state-equivalent to a successful deployment.
        P256PrecompileHalmosStub stub =
            P256PrecompileHalmosStub(address(uint160(uint256(keccak256("P256PrecompileHalmosStub")))));
        vm.etch(address(stub), type(P256PrecompileHalmosStub).runtimeCode);
        vm.etch(PRECOMPILE, address(stub).code);

        validator = P256Validator(address(uint160(uint256(keccak256("P256Validator")))));
        vm.etch(address(validator), type(P256Validator).runtimeCode);

        signer = P256Signer(address(uint160(uint256(keccak256("P256Signer")))));
        vm.etch(address(signer), type(P256Signer).runtimeCode);
    }

    function _setOracle(bool result) internal {
        vm.store(PRECOMPILE, bytes32(0), bytes32(uint256(result ? 1 : 0)));
    }

    function _key() internal pure returns (bytes memory) {
        return abi.encode(GX, GY);
    }

    function _signerInstallData(bytes32 id) internal pure returns (bytes memory) {
        return abi.encodePacked(id, abi.encode(GX, GY));
    }

    function _signature(uint256 r, uint256 s) internal pure returns (bytes memory) {
        return abi.encode(bytes32(r), bytes32(s));
    }

    function _selector(bytes memory returndata) internal pure returns (bytes4 result) {
        if (returndata.length >= 4) {
            assembly ("memory-safe") {
                result := mload(add(returndata, 0x20))
            }
        }
    }

    // =============================================================================================
    // LIFECYCLE AND STORAGE SEPARATION
    // =============================================================================================

    function check_Validator_lifecycleAndAccountSeparation() external {
        vm.prank(CALLER);
        validator.onInstall(_key());

        (uint256 x, uint256 y) = validator.p256ValidatorStorage(CALLER);
        assert(x == GX && y == GY);
        assert(validator.isInitialized(CALLER));

        (uint256 otherX, uint256 otherY) = validator.p256ValidatorStorage(OTHER);
        assert(otherX == 0 && otherY == 0);
        assert(!validator.isInitialized(OTHER));

        vm.prank(CALLER);
        validator.onUninstall("");
        (x, y) = validator.p256ValidatorStorage(CALLER);
        assert(x == 0 && y == 0);
        assert(!validator.isInitialized(CALLER));
    }

    function check_Validator_lifecycleGuards() external {
        vm.prank(CALLER);
        (bool ok, bytes memory ret) = address(validator).call(abi.encodeCall(validator.onInstall, (hex"01")));
        assert(!ok && _selector(ret) == INVALID_DATA_LENGTH);

        vm.prank(CALLER);
        (ok, ret) = address(validator).call(abi.encodeCall(validator.onInstall, (abi.encode(uint256(0), uint256(0)))));
        assert(!ok && _selector(ret) == INVALID_PUBLIC_KEY);

        vm.prank(CALLER);
        validator.onInstall(_key());
        vm.prank(CALLER);
        (ok, ret) = address(validator).call(abi.encodeCall(validator.onInstall, (_key())));
        assert(!ok && _selector(ret) == ALREADY_INITIALIZED);

        vm.prank(OTHER);
        (ok, ret) = address(validator).call(abi.encodeCall(validator.onUninstall, ("")));
        assert(!ok && _selector(ret) == NOT_INITIALIZED);
    }

    function check_Signer_lifecycleAndKeySeparation() external {
        vm.prank(CALLER);
        signer.onInstall(_signerInstallData(ID));

        (uint256 x, uint256 y) = signer.p256SignerStorage(ID, CALLER);
        assert(x == GX && y == GY);
        assert(signer.isInitialized(ID, CALLER));

        (uint256 otherAccountX, uint256 otherAccountY) = signer.p256SignerStorage(ID, OTHER);
        assert(otherAccountX == 0 && otherAccountY == 0);
        (uint256 otherIdX, uint256 otherIdY) = signer.p256SignerStorage(OTHER_ID, CALLER);
        assert(otherIdX == 0 && otherIdY == 0);

        vm.prank(CALLER);
        signer.onUninstall(abi.encodePacked(ID));
        (x, y) = signer.p256SignerStorage(ID, CALLER);
        assert(x == 0 && y == 0);
        assert(!signer.isInitialized(ID, CALLER));
    }

    function check_Signer_lifecycleGuards() external {
        vm.prank(CALLER);
        (bool ok, bytes memory ret) =
            address(signer).call(abi.encodeCall(signer.onInstall, (abi.encodePacked(ID, hex"01"))));
        assert(!ok && _selector(ret) == INVALID_DATA_LENGTH);

        vm.prank(CALLER);
        (ok, ret) = address(signer)
            .call(abi.encodeCall(signer.onInstall, (abi.encodePacked(ID, abi.encode(uint256(0), uint256(0))))));
        assert(!ok && _selector(ret) == INVALID_PUBLIC_KEY);

        vm.prank(CALLER);
        signer.onInstall(_signerInstallData(ID));
        vm.prank(CALLER);
        (ok, ret) = address(signer).call(abi.encodeCall(signer.onInstall, (_signerInstallData(ID))));
        assert(!ok && _selector(ret) == ALREADY_INITIALIZED);

        vm.prank(CALLER);
        (ok, ret) = address(signer).call(abi.encodeCall(signer.onUninstall, (abi.encodePacked(OTHER_ID))));
        assert(!ok && _selector(ret) == NOT_INITIALIZED);
    }

    // =============================================================================================
    // STATELESS ORACLE PLUMBING AND LOCAL GATES
    // =============================================================================================

    function check_StatelessOraclePlumbing(
        bytes32 hash,
        uint256 r,
        uint256 s,
        bool oracleResult,
        address requestingProtocol
    ) external {
        vm.assume(r > 0 && r < N);
        vm.assume(s > 0 && s <= HALF_N);
        _setOracle(oracleResult);

        bytes memory signature = _signature(r, s);
        bytes memory key = _key();

        bool validatorDirect = validator.validateSignatureWithData(hash, signature, key);
        bool validatorWithSender =
            validator.validateSignatureWithDataWithSender(requestingProtocol, hash, signature, key);
        bool signerDirect = signer.validateSignatureWithData(hash, signature, key);
        bool signerWithSender = signer.validateSignatureWithDataWithSender(requestingProtocol, hash, signature, key);

        assert(validatorDirect == oracleResult);
        assert(validatorWithSender == oracleResult);
        assert(signerDirect == oracleResult);
        assert(signerWithSender == oracleResult);
    }

    function check_StatelessLocalGuards(bytes32 hash) external {
        _setOracle(true);
        bytes memory validSignature = _signature(1, 1);
        bytes memory validKey = _key();

        assert(!validator.validateSignatureWithData(hash, validSignature, hex"01"));
        assert(!signer.validateSignatureWithData(hash, validSignature, hex"01"));

        bytes memory invalidKey = abi.encode(uint256(0), uint256(0));
        assert(!validator.validateSignatureWithData(hash, validSignature, invalidKey));
        assert(!signer.validateSignatureWithData(hash, validSignature, invalidKey));

        assert(!validator.validateSignatureWithData(hash, hex"01", validKey));
        assert(!signer.validateSignatureWithData(hash, hex"01", validKey));

        bytes memory highSSignature = _signature(1, HALF_N + 1);
        assert(!validator.validateSignatureWithData(hash, highSSignature, validKey));
        assert(!signer.validateSignatureWithData(hash, highSSignature, validKey));
    }

    function check_StatelessIgnoresInstalledState(bytes32 hash, bool oracleResult) external {
        _setOracle(oracleResult);
        bytes memory signature = _signature(1, 1);
        bytes memory key = _key();

        bool validatorBefore = validator.validateSignatureWithData(hash, signature, key);
        bool signerBefore = signer.validateSignatureWithData(hash, signature, key);

        vm.prank(CALLER);
        validator.onInstall(_key());
        vm.prank(CALLER);
        signer.onInstall(_signerInstallData(ID));

        bool validatorAfter = validator.validateSignatureWithData(hash, signature, key);
        bool signerAfter = signer.validateSignatureWithData(hash, signature, key);

        assert(validatorBefore == validatorAfter);
        assert(signerBefore == signerAfter);
        assert(validatorAfter == signerAfter);
    }

    // =============================================================================================
    // STATEFUL STORAGE GATES
    // =============================================================================================

    function check_StatefulValidationUsesOnlyScopedKey(bytes32 hash, bool oracleResult) external {
        _setOracle(oracleResult);
        bytes memory signature = _signature(1, 1);
        PackedUserOperation memory userOp;
        userOp.signature = signature;

        vm.prank(CALLER);
        validator.onInstall(_key());
        vm.prank(CALLER);
        signer.onInstall(_signerInstallData(ID));

        vm.prank(CALLER);
        uint256 validatorConfigured = validator.validateUserOp(userOp, hash);
        assert(validatorConfigured == (oracleResult ? SIG_VALIDATION_SUCCESS_UINT : SIG_VALIDATION_FAILED_UINT));

        vm.prank(OTHER);
        assert(validator.validateUserOp(userOp, hash) == SIG_VALIDATION_FAILED_UINT);

        vm.prank(CALLER);
        uint256 signerConfigured = signer.checkUserOpSignature(ID, userOp, hash);
        assert(signerConfigured == (oracleResult ? SIG_VALIDATION_SUCCESS_UINT : SIG_VALIDATION_FAILED_UINT));

        vm.prank(CALLER);
        assert(signer.checkUserOpSignature(OTHER_ID, userOp, hash) == SIG_VALIDATION_FAILED_UINT);
        vm.prank(OTHER);
        assert(signer.checkUserOpSignature(ID, userOp, hash) == SIG_VALIDATION_FAILED_UINT);

        vm.prank(OTHER);
        assert(validator.isValidSignatureWithSender(address(0), hash, signature) == ERC1271_INVALID);
        vm.prank(OTHER);
        assert(signer.checkSignature(ID, address(0), hash, signature) == ERC1271_INVALID);
    }

    // =============================================================================================
    // NON-VACUITY WITNESSES (counterexamples expected)
    // =============================================================================================

    function check_StatelessAcceptReachable(bytes32 hash) external {
        _setOracle(true);
        bool result = validator.validateSignatureWithData(hash, _signature(1, 1), _key());
        assert(!result);
    }

    function check_StatelessRejectReachable(bytes32 hash) external {
        _setOracle(false);
        bool result = signer.validateSignatureWithData(hash, _signature(1, 1), _key());
        assert(result);
    }
}
