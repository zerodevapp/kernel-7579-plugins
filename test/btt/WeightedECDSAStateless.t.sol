// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {WeightedECDSASigner} from "src/signers/WeightedECDSASigner.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";

/**
 * @title WeightedECDSAStatelessTest
 * @notice BTT tests for stateless signature validation
 */
contract WeightedECDSAStatelessTest is Test {
    WeightedECDSASigner signer;

    address guardian1;
    uint256 guardian1Key;
    address guardian2;
    uint256 guardian2Key;
    address guardian3;
    uint256 guardian3Key;

    // Sorted guardians
    address[] sortedGuardians;
    uint256[] sortedKeys;

    function setUp() public {
        signer = new WeightedECDSASigner();

        (guardian1, guardian1Key) = makeAddrAndKey("guardian1");
        (guardian2, guardian2Key) = makeAddrAndKey("guardian2");
        (guardian3, guardian3Key) = makeAddrAndKey("guardian3");

        // Sort guardians by address
        sortedGuardians = new address[](3);
        sortedKeys = new uint256[](3);

        sortedGuardians[0] = guardian1;
        sortedGuardians[1] = guardian2;
        sortedGuardians[2] = guardian3;
        sortedKeys[0] = guardian1Key;
        sortedKeys[1] = guardian2Key;
        sortedKeys[2] = guardian3Key;

        // Bubble sort
        for (uint256 i = 0; i < 3; i++) {
            for (uint256 j = i + 1; j < 3; j++) {
                if (sortedGuardians[i] > sortedGuardians[j]) {
                    (sortedGuardians[i], sortedGuardians[j]) = (sortedGuardians[j], sortedGuardians[i]);
                    (sortedKeys[i], sortedKeys[j]) = (sortedKeys[j], sortedKeys[i]);
                }
            }
        }
    }

    function _createData(uint24 threshold) internal view returns (bytes memory) {
        uint24[] memory weights = new uint24[](3);
        weights[0] = 40;
        weights[1] = 30;
        weights[2] = 30;
        return abi.encode(sortedGuardians, weights, threshold);
    }

    function _signHash(bytes32 hash, uint256[] memory keys) internal view returns (bytes memory) {
        bytes memory signatures;
        for (uint256 i = 0; i < keys.length; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[i], hash);
            signatures = abi.encodePacked(signatures, r, s, v);
        }
        return signatures;
    }

    // ============ Test Cases ============

    function test_WhenThresholdIsZero() external {
        bytes32 hash = keccak256("test");

        uint256[] memory keys = new uint256[](1);
        keys[0] = sortedKeys[0];
        bytes memory sig = _signHash(hash, keys);

        // Create data with threshold 0
        uint24[] memory weights = new uint24[](3);
        weights[0] = 40;
        weights[1] = 30;
        weights[2] = 30;
        bytes memory data = abi.encode(sortedGuardians, weights, uint24(0));

        // it should return false
        bool result = signer.validateSignatureWithData(hash, sig, data);
        assertFalse(result);
    }

    function test_WhenGuardiansAndWeightsLengthMismatch() external {
        bytes32 hash = keccak256("test");

        uint256[] memory keys = new uint256[](1);
        keys[0] = sortedKeys[0];
        bytes memory sig = _signHash(hash, keys);

        // Create data with mismatched lengths
        uint24[] memory weights = new uint24[](2); // Only 2 weights for 3 guardians
        weights[0] = 40;
        weights[1] = 30;
        bytes memory data = abi.encode(sortedGuardians, weights, uint24(50));

        // it should return false
        bool result = signer.validateSignatureWithData(hash, sig, data);
        assertFalse(result);
    }

    function test_WhenSignatureCountIsZero() external {
        bytes32 hash = keccak256("test");
        bytes memory sig = ""; // Empty signature

        bytes memory data = _createData(50);

        // it should return false
        bool result = signer.validateSignatureWithData(hash, sig, data);
        assertFalse(result);
    }

    function test_WhenNon_lastSignerIsNotInSortedOrder() external {
        bytes32 hash = keccak256("test");

        // Sign in wrong order: second guardian before first (for non-last signatures)
        bytes memory signatures;
        // Sign with higher address first (wrong order)
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(sortedKeys[1], hash);
        signatures = abi.encodePacked(signatures, r1, s1, v1);
        // Sign with lower address second (wrong order)
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(sortedKeys[0], hash);
        signatures = abi.encodePacked(signatures, r2, s2, v2);
        // Last signature
        (uint8 v3, bytes32 r3, bytes32 s3) = vm.sign(sortedKeys[2], hash);
        signatures = abi.encodePacked(signatures, r3, s3, v3);

        bytes memory data = _createData(50);

        // it should return false
        bool result = signer.validateSignatureWithData(hash, signatures, data);
        assertFalse(result);
    }

    function test_WhenThresholdIsMetBeforeLastSignature() external {
        bytes32 hash = keccak256("test");

        // Sign with first two guardians (40 + 30 = 70 >= threshold 50)
        uint256[] memory keys = new uint256[](3);
        keys[0] = sortedKeys[0];
        keys[1] = sortedKeys[1];
        keys[2] = sortedKeys[2];
        bytes memory sig = _signHash(hash, keys);

        // Threshold 50, first two guardians have 70 weight combined
        bytes memory data = _createData(50);

        // it should return true early
        bool result = signer.validateSignatureWithData(hash, sig, data);
        assertTrue(result);
    }

    function test_WhenLastSignerIsNotInSortedOrder() external {
        bytes32 hash = keccak256("test");

        // Sign with first guardian, then last signer has lower address
        // This requires creating a scenario where last signer address < previous signer address
        // We'll use only the highest address guardian first, then a lower one last
        bytes memory signatures;
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(sortedKeys[2], hash); // Highest address
        signatures = abi.encodePacked(signatures, r1, s1, v1);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(sortedKeys[0], hash); // Lowest address (wrong order)
        signatures = abi.encodePacked(signatures, r2, s2, v2);

        bytes memory data = _createData(50);

        // it should return false
        bool result = signer.validateSignatureWithData(hash, signatures, data);
        assertFalse(result);
    }

    function test_WhenLastSignerHasZeroWeight() external {
        bytes32 hash = keccak256("test");

        // Create a non-guardian that will be last
        (address nonGuardian, uint256 nonGuardianKey) = makeAddrAndKey("zzz_nonGuardian");

        // Sign with first guardian, then non-guardian (zero weight) as last
        bytes memory signatures;
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(sortedKeys[0], hash);
        signatures = abi.encodePacked(signatures, r1, s1, v1);

        // Make sure nonGuardian is higher than sortedGuardians[0]
        require(nonGuardian > sortedGuardians[0], "Test setup: nonGuardian must be higher");

        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(nonGuardianKey, hash);
        signatures = abi.encodePacked(signatures, r2, s2, v2);

        bytes memory data = _createData(50);

        // it should return false
        bool result = signer.validateSignatureWithData(hash, signatures, data);
        assertFalse(result);
    }

    function test_WhenNon_lastSignerHasZeroWeight() external {
        bytes32 hash = keccak256("test");

        // We need a non-guardian that is NOT the last signer
        // We'll use 2 signers: nonGuardian first, then a valid guardian last
        // Sign nonGuardian first, then highest guardian last
        uint256 nonGuardianKey = 0x1234567890abcdef;
        address nonGuardian = vm.addr(nonGuardianKey);

        // Find a key that gives an address lower than the highest guardian
        while (nonGuardian >= sortedGuardians[2]) {
            nonGuardianKey += 1;
            nonGuardian = vm.addr(nonGuardianKey);
        }

        // Sign in order: nonGuardian (low address, zero weight), then highest guardian (valid)
        bytes memory signatures;
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(nonGuardianKey, hash);
        signatures = abi.encodePacked(signatures, r1, s1, v1);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(sortedKeys[2], hash);
        signatures = abi.encodePacked(signatures, r2, s2, v2);

        bytes memory data = _createData(50);

        // it should revert with ZeroWeightSigner (nonGuardian is not last)
        vm.expectRevert(WeightedECDSASigner.ZeroWeightSigner.selector);
        signer.validateSignatureWithData(hash, signatures, data);
    }

    function test_WhenAllSignersAreValidAndThresholdIsMet() external {
        bytes32 hash = keccak256("test");

        // Sign with all three guardians in sorted order
        uint256[] memory keys = new uint256[](3);
        keys[0] = sortedKeys[0];
        keys[1] = sortedKeys[1];
        keys[2] = sortedKeys[2];
        bytes memory sig = _signHash(hash, keys);

        bytes memory data = _createData(100); // Threshold 100, total weight is 100

        // it should return true
        bool result = signer.validateSignatureWithData(hash, sig, data);
        assertTrue(result);
    }

    function test_WhenSingleSignatureMeetsThreshold() external {
        bytes32 hash = keccak256("test");

        // Sign with only first guardian
        uint256[] memory keys = new uint256[](1);
        keys[0] = sortedKeys[0];
        bytes memory sig = _signHash(hash, keys);

        // First guardian has weight 40, set threshold to 40
        uint24[] memory weights = new uint24[](3);
        weights[0] = 40;
        weights[1] = 30;
        weights[2] = 30;
        bytes memory data = abi.encode(sortedGuardians, weights, uint24(40));

        // it should return true with single signature
        bool result = signer.validateSignatureWithData(hash, sig, data);
        assertTrue(result);
    }

    function test_WhenSingleSignatureDoesNotMeetThreshold() external {
        bytes32 hash = keccak256("test");

        // Sign with only first guardian
        uint256[] memory keys = new uint256[](1);
        keys[0] = sortedKeys[0];
        bytes memory sig = _signHash(hash, keys);

        // First guardian has weight 40, threshold 50 - should fail
        bytes memory data = _createData(50);

        // it should return false
        bool result = signer.validateSignatureWithData(hash, sig, data);
        assertFalse(result);
    }

    function test_WhenValidatingSignatureWithDataWithSenderSucceeds() external {
        bytes32 hash = keccak256("test");

        uint256[] memory keys = new uint256[](2);
        keys[0] = sortedKeys[0];
        keys[1] = sortedKeys[1];
        bytes memory sig = _signHash(hash, keys);

        bytes memory data = _createData(50);

        // it should return true via validateSignatureWithDataWithSender
        bool result = signer.validateSignatureWithDataWithSender(address(0x5678), hash, sig, data);
        assertTrue(result);
    }

    function test_WhenValidatingSignatureWithDataWithSenderFails() external {
        bytes32 hash = keccak256("test");
        bytes memory sig = ""; // Empty signature

        bytes memory data = _createData(50);

        // it should return false via validateSignatureWithDataWithSender
        bool result = signer.validateSignatureWithDataWithSender(address(0x5678), hash, sig, data);
        assertFalse(result);
    }
}
