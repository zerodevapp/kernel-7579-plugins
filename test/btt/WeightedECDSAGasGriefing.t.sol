// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {WeightedECDSASigner} from "src/signers/WeightedECDSASigner.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {
    ERC1271_MAGICVALUE,
    ERC1271_INVALID,
    SIG_VALIDATION_FAILED_UINT,
    SIG_VALIDATION_SUCCESS_UINT
} from "src/types/Constants.sol";

/**
 * @title WeightedECDSAGasGriefingTest
 * @notice BTT tests for the MAX_SIGNATURES protection in WeightedECDSASigner
 * @dev Tests the fix for TOB-KERNEL-15: Gas griefing through excessive signatures
 */
contract WeightedECDSAGasGriefingTest is Test {
    WeightedECDSASigner signer;
    IEntryPoint entrypoint;

    address constant WALLET = address(0x1234);
    bytes32 constant SIGNER_ID = keccak256("TEST_SIGNER_ID");

    // We need 11 guardians to test MAX_SIGNATURES (10) boundary
    address[] guardians;
    uint256[] guardianKeys;

    uint24 constant WEIGHT_PER_GUARDIAN = 10;
    uint24 constant THRESHOLD = 50; // Need 5 guardians to meet threshold

    function setUp() public {
        signer = new WeightedECDSASigner();
        entrypoint = EntryPointLib.deploy();

        // Create 11 guardians for testing MAX_SIGNATURES boundary
        for (uint256 i = 0; i < 11; i++) {
            (address guardian, uint256 key) = makeAddrAndKey(string(abi.encodePacked("guardian", i)));
            guardians.push(guardian);
            guardianKeys.push(key);
        }

        // Sort guardians by address (ascending order) - bubble sort
        for (uint256 i = 0; i < guardians.length; i++) {
            for (uint256 j = i + 1; j < guardians.length; j++) {
                if (guardians[i] > guardians[j]) {
                    (guardians[i], guardians[j]) = (guardians[j], guardians[i]);
                    (guardianKeys[i], guardianKeys[j]) = (guardianKeys[j], guardianKeys[i]);
                }
            }
        }
    }

    function _installSigner(uint256 numGuardians) internal {
        address[] memory guardiansToInstall = new address[](numGuardians);
        uint24[] memory weights = new uint24[](numGuardians);

        for (uint256 i = 0; i < numGuardians; i++) {
            guardiansToInstall[i] = guardians[i];
            weights[i] = WEIGHT_PER_GUARDIAN;
        }

        bytes memory installData = abi.encode(guardiansToInstall, weights, THRESHOLD);

        vm.prank(WALLET);
        signer.onInstall(abi.encodePacked(SIGNER_ID, installData));
    }

    function _signHash(bytes32 hash, uint256 numSigners) internal view returns (bytes memory) {
        bytes memory signatures;

        for (uint256 i = 0; i < numSigners; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(guardianKeys[i], hash);
            signatures = abi.encodePacked(signatures, r, s, v);
        }

        return signatures;
    }

    function _signHashWithNonGuardians(bytes32 hash, uint256 numSigners) internal returns (bytes memory) {
        bytes memory signatures;

        // Create and sort non-guardian addresses
        address[] memory nonGuardians = new address[](numSigners);
        uint256[] memory nonGuardianKeys = new uint256[](numSigners);

        for (uint256 i = 0; i < numSigners; i++) {
            (address addr, uint256 key) = makeAddrAndKey(string(abi.encodePacked("nonguardian", i)));
            nonGuardians[i] = addr;
            nonGuardianKeys[i] = key;
        }

        // Sort non-guardians by address
        for (uint256 i = 0; i < numSigners; i++) {
            for (uint256 j = i + 1; j < numSigners; j++) {
                if (nonGuardians[i] > nonGuardians[j]) {
                    (nonGuardians[i], nonGuardians[j]) = (nonGuardians[j], nonGuardians[i]);
                    (nonGuardianKeys[i], nonGuardianKeys[j]) = (nonGuardianKeys[j], nonGuardianKeys[i]);
                }
            }
        }

        for (uint256 i = 0; i < numSigners; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(nonGuardianKeys[i], hash);
            signatures = abi.encodePacked(signatures, r, s, v);
        }

        return signatures;
    }

    // ============ Test Cases ============

    function test_WhenSignatureCountExceedsMAX_SIGNATURES() external {
        // Install 11 guardians (more than MAX_SIGNATURES of 10)
        _installSigner(11);

        bytes32 testHash = keccak256("test");

        // Create 11 signatures (exceeds MAX_SIGNATURES of 10)
        bytes memory signatures = _signHash(testHash, 11);

        vm.prank(WALLET);
        bytes4 result = signer.checkSignature(SIGNER_ID, address(0), testHash, signatures);

        // it should return ERC1271_INVALID
        assertEq(result, ERC1271_INVALID, "Should fail when signature count exceeds MAX_SIGNATURES");
    }

    function test_WhenSignatureCountEqualsMAX_SIGNATURESWithValidGuardians() external {
        // Install 10 guardians (exactly MAX_SIGNATURES)
        _installSigner(10);

        bytes32 testHash = keccak256("test");

        // Create exactly 10 signatures from valid guardians
        bytes memory signatures = _signHash(testHash, 10);

        vm.prank(WALLET);
        bytes4 result = signer.checkSignature(SIGNER_ID, address(0), testHash, signatures);

        // it should return ERC1271_MAGICVALUE (10 guardians * 10 weight = 100 >= threshold 50)
        assertEq(result, ERC1271_MAGICVALUE, "Should succeed with exactly MAX_SIGNATURES valid guardians");
    }

    function test_WhenSignatureCountEqualsMAX_SIGNATURESWithNon_guardians() external {
        // Install only 5 guardians but provide 10 signatures from non-guardians
        _installSigner(5);

        bytes32 testHash = keccak256("test");

        // Create 10 signatures from non-guardians
        bytes memory signatures = _signHashWithNonGuardians(testHash, 10);

        vm.prank(WALLET);
        bytes4 result = signer.checkSignature(SIGNER_ID, address(0), testHash, signatures);

        // it should return ERC1271_INVALID when threshold not met (non-guardians have 0 weight)
        assertEq(result, ERC1271_INVALID, "Should fail when non-guardians cannot meet threshold");
    }

    function test_WhenSignatureCountIsLessThanMAX_SIGNATURES() external {
        // Install 5 guardians
        _installSigner(5);

        bytes32 testHash = keccak256("test");

        // Create 5 signatures (less than MAX_SIGNATURES of 10)
        bytes memory signatures = _signHash(testHash, 5);

        vm.prank(WALLET);
        bytes4 result = signer.checkSignature(SIGNER_ID, address(0), testHash, signatures);

        // it should validate normally and succeed when threshold met (5 * 10 = 50 >= threshold 50)
        assertEq(result, ERC1271_MAGICVALUE, "Should succeed with less than MAX_SIGNATURES when threshold met");
    }

    function test_WhenSignatureCountIsZero() external {
        _installSigner(5);

        bytes32 testHash = keccak256("test");

        // Empty signature
        bytes memory signatures = "";

        vm.prank(WALLET);
        bytes4 result = signer.checkSignature(SIGNER_ID, address(0), testHash, signatures);

        // it should return ERC1271_INVALID
        assertEq(result, ERC1271_INVALID, "Should fail with zero signatures");
    }

    function test_WhenSignatureLengthIsNotAMultipleOf65() external {
        _installSigner(5);

        bytes32 testHash = keccak256("test");

        // Create a signature that is not a multiple of 65 bytes (e.g., 100 bytes)
        bytes memory signatures = new bytes(100);

        vm.prank(WALLET);
        bytes4 result = signer.checkSignature(SIGNER_ID, address(0), testHash, signatures);

        // it should return ERC1271_INVALID
        assertEq(result, ERC1271_INVALID, "Should fail when signature length is not multiple of 65");
    }

    function test_WhenERC1271SignatureCountExceedsMAX_SIGNATURES() external {
        // Install 11 guardians
        _installSigner(11);

        bytes32 testHash = keccak256("test");

        // Create 11 signatures (exceeds MAX_SIGNATURES of 10)
        bytes memory signatures = _signHash(testHash, 11);

        vm.prank(WALLET);
        bytes4 result = signer.checkSignature(SIGNER_ID, address(0), testHash, signatures);

        // it should return ERC1271_INVALID
        assertEq(result, ERC1271_INVALID, "ERC1271 should fail when signature count exceeds MAX_SIGNATURES");
    }

    function test_WhenSignerHasZeroWeightInGuardianStorage() external {
        // Install 5 guardians with weight
        _installSigner(5);

        bytes32 testHash = keccak256("test");

        // Sign with a non-guardian (who has zero weight) plus 4 valid guardians
        // Total weight will be: 0 (non-guardian) + 4*10 = 40 < threshold 50
        (address nonGuardian, uint256 nonGuardianKey) = makeAddrAndKey("zeroWeightSigner");

        // We need to create a sorted signature array including the non-guardian
        // First, find where non-guardian fits in the sorted order
        address[] memory mixedSigners = new address[](5);
        uint256[] memory mixedKeys = new uint256[](5);

        // Use 4 guardians + 1 non-guardian
        mixedSigners[0] = nonGuardian;
        mixedKeys[0] = nonGuardianKey;
        for (uint256 i = 0; i < 4; i++) {
            mixedSigners[i + 1] = guardians[i];
            mixedKeys[i + 1] = guardianKeys[i];
        }

        // Sort
        for (uint256 i = 0; i < 5; i++) {
            for (uint256 j = i + 1; j < 5; j++) {
                if (mixedSigners[i] > mixedSigners[j]) {
                    (mixedSigners[i], mixedSigners[j]) = (mixedSigners[j], mixedSigners[i]);
                    (mixedKeys[i], mixedKeys[j]) = (mixedKeys[j], mixedKeys[i]);
                }
            }
        }

        // Create signatures
        bytes memory signatures;
        for (uint256 i = 0; i < 5; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(mixedKeys[i], testHash);
            signatures = abi.encodePacked(signatures, r, s, v);
        }

        vm.prank(WALLET);
        bytes4 result = signer.checkSignature(SIGNER_ID, address(0), testHash, signatures);

        // it should not contribute to threshold accumulation
        // 4 valid guardians * 10 weight = 40 < threshold 50, so should fail
        assertEq(result, ERC1271_INVALID, "Zero-weight signer should not contribute to threshold");
    }

    function test_WhenMultipleZero_weightSignersAreProvided() external {
        // Install only 2 guardians with weight
        address[] memory guardiansToInstall = new address[](2);
        uint24[] memory weights = new uint24[](2);
        guardiansToInstall[0] = guardians[0];
        guardiansToInstall[1] = guardians[1];
        weights[0] = WEIGHT_PER_GUARDIAN;
        weights[1] = WEIGHT_PER_GUARDIAN;

        bytes memory installData = abi.encode(guardiansToInstall, weights, THRESHOLD);

        vm.prank(WALLET);
        signer.onInstall(abi.encodePacked(SIGNER_ID, installData));

        bytes32 testHash = keccak256("test");

        // Create 5 non-guardian signers
        address[] memory nonGuardians = new address[](5);
        uint256[] memory nonGuardianKeys = new uint256[](5);

        for (uint256 i = 0; i < 5; i++) {
            (address addr, uint256 key) = makeAddrAndKey(string(abi.encodePacked("multiZero", i)));
            nonGuardians[i] = addr;
            nonGuardianKeys[i] = key;
        }

        // Sort non-guardians
        for (uint256 i = 0; i < 5; i++) {
            for (uint256 j = i + 1; j < 5; j++) {
                if (nonGuardians[i] > nonGuardians[j]) {
                    (nonGuardians[i], nonGuardians[j]) = (nonGuardians[j], nonGuardians[i]);
                    (nonGuardianKeys[i], nonGuardianKeys[j]) = (nonGuardianKeys[j], nonGuardianKeys[i]);
                }
            }
        }

        // Create signatures from non-guardians
        bytes memory signatures;
        for (uint256 i = 0; i < 5; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(nonGuardianKeys[i], testHash);
            signatures = abi.encodePacked(signatures, r, s, v);
        }

        vm.prank(WALLET);
        bytes4 result = signer.checkSignature(SIGNER_ID, address(0), testHash, signatures);

        // it should fail to meet threshold (all signers have 0 weight)
        assertEq(result, ERC1271_INVALID, "Multiple zero-weight signers should fail to meet threshold");
    }
}
