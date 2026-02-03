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
 * @notice BTT tests for gas griefing protection in WeightedECDSASigner
 * @dev Tests the fix for TOB-KERNEL-15: Gas griefing through zero-weight signers
 *      - Non-last signers with zero weight cause a revert (prevents gas griefing)
 *      - Last signer with zero weight returns validation failed (allows proper UX)
 */
contract WeightedECDSAGasGriefingTest is Test {
    WeightedECDSASigner signer;
    IEntryPoint entrypoint;

    address constant WALLET = address(0x1234);
    bytes32 constant SIGNER_ID = keccak256("TEST_SIGNER_ID");

    // Guardians for testing
    address[] guardians;
    uint256[] guardianKeys;

    uint24 constant WEIGHT_PER_GUARDIAN = 10;
    uint24 constant THRESHOLD = 50; // Need 5 guardians to meet threshold

    function setUp() public {
        signer = new WeightedECDSASigner();
        entrypoint = EntryPointLib.deploy();

        // Create 15 guardians for testing (more than old MAX_SIGNATURES of 10)
        for (uint256 i = 0; i < 15; i++) {
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

    // ============ Test Cases ============

    function test_WhenNonLastSignerHasZeroWeight() external {
        // Install 5 guardians with weight
        _installSigner(5);

        bytes32 testHash = keccak256("test");

        // Create a signature where a non-guardian is NOT the last signer
        // We'll use: nonGuardian, guardian[0], guardian[1], guardian[2], guardian[3]
        // But sorted, so nonGuardian could be anywhere except last
        (address nonGuardian, uint256 nonGuardianKey) = makeAddrAndKey("zeroWeightSignerFirst");

        // Find position where non-guardian fits (must not be last after sorting)
        address[] memory mixedSigners = new address[](5);
        uint256[] memory mixedKeys = new uint256[](5);

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

        // Check if nonGuardian is last - if so, we need a different nonGuardian
        // For this test, we want nonGuardian to NOT be last
        // Let's find a non-guardian that sorts before our last guardian
        bool nonGuardianIsLast = mixedSigners[4] == nonGuardian;

        if (nonGuardianIsLast) {
            // Use a lower address non-guardian
            (nonGuardian, nonGuardianKey) = makeAddrAndKey("aaa_zeroWeight");
            mixedSigners[0] = nonGuardian;
            mixedKeys[0] = nonGuardianKey;

            // Re-sort
            for (uint256 i = 0; i < 5; i++) {
                for (uint256 j = i + 1; j < 5; j++) {
                    if (mixedSigners[i] > mixedSigners[j]) {
                        (mixedSigners[i], mixedSigners[j]) = (mixedSigners[j], mixedSigners[i]);
                        (mixedKeys[i], mixedKeys[j]) = (mixedKeys[j], mixedKeys[i]);
                    }
                }
            }
        }

        // Create signatures
        bytes memory signatures;
        for (uint256 i = 0; i < 5; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(mixedKeys[i], testHash);
            signatures = abi.encodePacked(signatures, r, s, v);
        }

        // it should revert with ZeroWeightSigner
        vm.prank(WALLET);
        vm.expectRevert(WeightedECDSASigner.ZeroWeightSigner.selector);
        signer.checkSignature(SIGNER_ID, address(0), testHash, signatures);
    }

    function test_WhenLastSignerHasZeroWeight() external {
        // Install 5 guardians with weight
        _installSigner(5);

        bytes32 testHash = keccak256("test");

        // Create a signature where a non-guardian IS the last signer (highest address)
        // Use guardians 0-3 (4 guardians) + one non-guardian that sorts last
        (address nonGuardian, uint256 nonGuardianKey) = makeAddrAndKey("zzz_lastNonGuardian");

        address[] memory mixedSigners = new address[](5);
        uint256[] memory mixedKeys = new uint256[](5);

        for (uint256 i = 0; i < 4; i++) {
            mixedSigners[i] = guardians[i];
            mixedKeys[i] = guardianKeys[i];
        }
        mixedSigners[4] = nonGuardian;
        mixedKeys[4] = nonGuardianKey;

        // Sort to ensure nonGuardian ends up last
        for (uint256 i = 0; i < 5; i++) {
            for (uint256 j = i + 1; j < 5; j++) {
                if (mixedSigners[i] > mixedSigners[j]) {
                    (mixedSigners[i], mixedSigners[j]) = (mixedSigners[j], mixedSigners[i]);
                    (mixedKeys[i], mixedKeys[j]) = (mixedKeys[j], mixedKeys[i]);
                }
            }
        }

        // Verify nonGuardian is actually last
        require(mixedSigners[4] == nonGuardian, "Test setup: nonGuardian should be last");

        // Create signatures
        bytes memory signatures;
        for (uint256 i = 0; i < 5; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(mixedKeys[i], testHash);
            signatures = abi.encodePacked(signatures, r, s, v);
        }

        // it should return ERC1271_INVALID (not revert)
        vm.prank(WALLET);
        bytes4 result = signer.checkSignature(SIGNER_ID, address(0), testHash, signatures);
        assertEq(result, ERC1271_INVALID, "Last signer with zero weight should return invalid, not revert");
    }

    function test_WhenAllSignersAreValidGuardians() external {
        // Install 5 guardians
        _installSigner(5);

        bytes32 testHash = keccak256("test");

        // Create 5 signatures from valid guardians
        bytes memory signatures = _signHash(testHash, 5);

        vm.prank(WALLET);
        bytes4 result = signer.checkSignature(SIGNER_ID, address(0), testHash, signatures);

        // it should validate normally and succeed when threshold met (5 * 10 = 50 >= threshold 50)
        assertEq(result, ERC1271_MAGICVALUE, "Should succeed when all signers are valid guardians");
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

    function test_WhenMoreThan10ValidGuardiansSigning() external {
        // Install 12 guardians (more than the old MAX_SIGNATURES of 10)
        _installSigner(12);

        bytes32 testHash = keccak256("test");

        // Create 12 signatures from valid guardians
        bytes memory signatures = _signHash(testHash, 12);

        vm.prank(WALLET);
        bytes4 result = signer.checkSignature(SIGNER_ID, address(0), testHash, signatures);

        // it should succeed - no arbitrary limit on number of signatures
        // 12 guardians * 10 weight = 120 >= threshold 50
        assertEq(result, ERC1271_MAGICVALUE, "Should succeed with more than 10 valid guardians (no arbitrary limit)");
    }

    function test_WhenOnlyLastSignatureIsFromNonGuardian() external {
        // Install 5 guardians
        _installSigner(5);

        bytes32 testHash = keccak256("test");

        // Use a non-guardian that will sort to be last
        (address nonGuardian, uint256 nonGuardianKey) = makeAddrAndKey("zzzzzzz_veryLast");

        // Sign with 4 guardians + 1 non-guardian (last)
        bytes memory signatures;
        for (uint256 i = 0; i < 4; i++) {
            (uint8 vi, bytes32 ri, bytes32 si) = vm.sign(guardianKeys[i], testHash);
            signatures = abi.encodePacked(signatures, ri, si, vi);
        }

        // Ensure nonGuardian address is actually higher than all 4 guardians used
        require(nonGuardian > guardians[3], "Test setup: nonGuardian must sort after guardians[3]");

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(nonGuardianKey, testHash);
        signatures = abi.encodePacked(signatures, r, s, v);

        vm.prank(WALLET);
        bytes4 result = signer.checkSignature(SIGNER_ID, address(0), testHash, signatures);

        // it should return ERC1271_INVALID without reverting
        // 4 valid guardians * 10 = 40 < threshold 50, and last signer has 0 weight
        assertEq(result, ERC1271_INVALID, "Should return invalid when only last signature is non-guardian");
    }
}
