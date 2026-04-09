// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {WeightedECDSASigner} from "src/signers/WeightedECDSASigner.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {SIG_VALIDATION_FAILED_UINT, SIG_VALIDATION_SUCCESS_UINT} from "src/types/Constants.sol";

/// @title WeightedECDSAUserOpHashTest
/// @notice BTT tests for the security fix on branch fix/tob-kernel-16
/// @dev Tests the fix for: Weighted validator can skip userOpHash, allowing mutable user operations
contract WeightedECDSAUserOpHashTest is Test {
    WeightedECDSASigner public signerModule;
    IEntryPoint public ENTRYPOINT;

    address constant WALLET = address(0x1234);
    bytes32 constant SIGNER_ID = keccak256(abi.encodePacked("BTT_SIGNER_ID"));

    // Guardian keys - will be sorted by address after generation
    address public guardian1;
    uint256 public guardian1Key;
    address public guardian2;
    uint256 public guardian2Key;
    address public guardian3;
    uint256 public guardian3Key;

    // Weights and threshold
    uint24 public weight1 = 50;
    uint24 public weight2 = 30;
    uint24 public weight3 = 20;
    uint24 public threshold = 60; // Need guardian1 + guardian2 (50 + 30 = 80) to meet threshold

    function setUp() public {
        signerModule = new WeightedECDSASigner();
        ENTRYPOINT = EntryPointLib.deploy();

        // Generate guardian keys
        (guardian1, guardian1Key) = makeAddrAndKey("guardian1");
        (guardian2, guardian2Key) = makeAddrAndKey("guardian2");
        (guardian3, guardian3Key) = makeAddrAndKey("guardian3");

        // Install the signer module with guardians
        _installModule();
    }

    function _installModule() internal {
        address[] memory guardians = new address[](3);
        guardians[0] = guardian1;
        guardians[1] = guardian2;
        guardians[2] = guardian3;

        uint24[] memory weights = new uint24[](3);
        weights[0] = weight1;
        weights[1] = weight2;
        weights[2] = weight3;

        bytes memory installData = abi.encode(guardians, weights, threshold);

        vm.prank(WALLET);
        signerModule.onInstall(abi.encodePacked(SIGNER_ID, installData));
    }

    function _createUserOp() internal view returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: WALLET,
            nonce: 0,
            initCode: "",
            callData: abi.encodeWithSignature("execute(address,uint256,bytes)", address(0x5678), 0, ""),
            accountGasLimits: bytes32(abi.encodePacked(uint128(100000), uint128(200000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: "",
            signature: ""
        });
    }

    function _computeProposalHash(PackedUserOperation memory userOp) internal view returns (bytes32) {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("WeightedECDSASigner"),
                keccak256("0.0.2"),
                block.chainid,
                address(signerModule)
            )
        );

        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator,
                keccak256(
                    abi.encode(
                        keccak256("Proposal(address account,bytes32 id,bytes callData,uint256 nonce)"),
                        userOp.sender,
                        SIGNER_ID,
                        keccak256(userOp.callData),
                        userOp.nonce
                    )
                )
            )
        );
    }

    /// @dev Sort two signers and return signatures in sorted order
    function _sortAndSignProposalHash(
        bytes32 proposalHash,
        address signerA,
        uint256 keyA,
        address signerB,
        uint256 keyB
    ) internal pure returns (bytes memory) {
        (uint8 vA, bytes32 rA, bytes32 sA) = vm.sign(keyA, proposalHash);
        (uint8 vB, bytes32 rB, bytes32 sB) = vm.sign(keyB, proposalHash);

        if (signerA < signerB) {
            return abi.encodePacked(rA, sA, vA, rB, sB, vB);
        } else {
            return abi.encodePacked(rB, sB, vB, rA, sA, vA);
        }
    }

    /// @dev Sign userOpHash (last signature, no sorting required)
    function _signUserOpHash(bytes32 userOpHash, uint256 key) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, userOpHash);
        return abi.encodePacked(r, s, v);
    }

    // ==================== Test Cases ====================

    function test_WhenUserOpHashSignerIsNotAValidGuardian() external {
        // it should return SIG_VALIDATION_FAILED_UINT

        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);
        bytes32 proposalHash = _computeProposalHash(userOp);

        // Create a non-guardian signer
        (address invalidSigner, uint256 invalidKey) = makeAddrAndKey("invalidSigner");

        // Guardian1 signs proposalHash (valid)
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(guardian1Key, proposalHash);

        // Invalid signer signs userOpHash
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(invalidKey, userOpHash);

        // Build signature: guardian1 (proposalHash) + invalidSigner (userOpHash)
        bytes memory signature;
        if (guardian1 < invalidSigner) {
            signature = abi.encodePacked(r1, s1, v1, r2, s2, v2);
        } else {
            // Need to swap order for proposalHash signers, but last sig is always userOpHash
            signature = abi.encodePacked(r1, s1, v1, r2, s2, v2);
        }

        userOp.signature = signature;

        vm.prank(WALLET);
        uint256 result = signerModule.checkUserOpSignature(SIGNER_ID, userOp, userOpHash);

        assertEq(result, SIG_VALIDATION_FAILED_UINT, "Should fail when userOpHash signer is not a valid guardian");
    }

    modifier whenSameGuardianSignsBothProposalHashAndUserOpHash() {
        _;
    }

    function test_GivenTheGuardianWeightAloneDoesNotMeetThreshold()
        external
        whenSameGuardianSignsBothProposalHashAndUserOpHash
    {
        // it should return SIG_VALIDATION_FAILED_UINT because weight is not double counted

        // Setup: Use guardian3 (weight 20) who alone doesn't meet threshold (60)
        // Even if they sign both proposalHash and userOpHash, weight should not be double-counted

        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);
        bytes32 proposalHash = _computeProposalHash(userOp);

        // Guardian3 signs proposalHash
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(guardian3Key, proposalHash);

        // Guardian3 also signs userOpHash
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(guardian3Key, userOpHash);

        // Build signature: guardian3 (proposalHash) + guardian3 (userOpHash)
        bytes memory signature = abi.encodePacked(r1, s1, v1, r2, s2, v2);

        userOp.signature = signature;

        vm.prank(WALLET);
        uint256 result = signerModule.checkUserOpSignature(SIGNER_ID, userOp, userOpHash);

        assertEq(result, SIG_VALIDATION_FAILED_UINT, "Should fail when same guardian's weight is not double-counted");
    }

    function test_GivenTheGuardianWeightAloneMeetsThreshold()
        external
        whenSameGuardianSignsBothProposalHashAndUserOpHash
    {
        // it should return SIG_VALIDATION_SUCCESS_UINT without double counting

        // For this test, we need to set up a scenario where a single guardian's weight meets threshold
        // We'll create a new module installation with guardian1 having weight >= threshold

        // Deploy new module for this specific test
        WeightedECDSASigner testModule = new WeightedECDSASigner();

        address[] memory guardians = new address[](1);
        guardians[0] = guardian1;

        uint24[] memory weights = new uint24[](1);
        weights[0] = 100; // Weight meets threshold of 60

        uint24 testThreshold = 60;

        bytes memory installData = abi.encode(guardians, weights, testThreshold);

        vm.prank(WALLET);
        testModule.onInstall(abi.encodePacked(SIGNER_ID, installData));

        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);

        // Compute proposal hash for the test module
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("WeightedECDSASigner"),
                keccak256("0.0.2"),
                block.chainid,
                address(testModule)
            )
        );

        bytes32 proposalHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator,
                keccak256(
                    abi.encode(
                        keccak256("Proposal(address account,bytes32 id,bytes callData,uint256 nonce)"),
                        userOp.sender,
                        SIGNER_ID,
                        keccak256(userOp.callData),
                        userOp.nonce
                    )
                )
            )
        );

        // Guardian1 signs proposalHash
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(guardian1Key, proposalHash);

        // Guardian1 also signs userOpHash
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(guardian1Key, userOpHash);

        // Build signature: guardian1 (proposalHash) + guardian1 (userOpHash)
        bytes memory signature = abi.encodePacked(r1, s1, v1, r2, s2, v2);

        userOp.signature = signature;

        vm.prank(WALLET);
        uint256 result = testModule.checkUserOpSignature(SIGNER_ID, userOp, userOpHash);

        assertEq(
            result,
            SIG_VALIDATION_SUCCESS_UINT,
            "Should succeed when guardian weight meets threshold even without double counting"
        );
    }

    function test_WhenProposalHashSignaturesReachThresholdButUserOpHashIsMissing() external {
        // it should return SIG_VALIDATION_FAILED_UINT because userOpHash is always required

        // This test verifies that even if proposalHash signatures reach threshold,
        // validation fails if the last signature (userOpHash) is not from a valid guardian

        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);
        bytes32 proposalHash = _computeProposalHash(userOp);

        // Guardian1 (50) + Guardian2 (30) = 80 >= threshold (60)
        // Both sign proposalHash, but the "userOpHash" slot will have an invalid signature

        // Sort guardian1 and guardian2
        address lowerAddr;
        address higherAddr;
        uint256 lowerKey;
        uint256 higherKey;

        if (guardian1 < guardian2) {
            lowerAddr = guardian1;
            lowerKey = guardian1Key;
            higherAddr = guardian2;
            higherKey = guardian2Key;
        } else {
            lowerAddr = guardian2;
            lowerKey = guardian2Key;
            higherAddr = guardian1;
            higherKey = guardian1Key;
        }

        // Sign proposalHash with sorted order
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(lowerKey, proposalHash);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(higherKey, proposalHash);

        // Create an invalid last signature (wrong hash - not userOpHash)
        bytes32 wrongHash = keccak256("wrong");
        (address invalidSigner, uint256 invalidKey) = makeAddrAndKey("invalid");
        (uint8 v3, bytes32 r3, bytes32 s3) = vm.sign(invalidKey, wrongHash);

        // Build signature: two proposalHash sigs + invalid userOpHash sig
        bytes memory signature = abi.encodePacked(r1, s1, v1, r2, s2, v2, r3, s3, v3);

        userOp.signature = signature;

        vm.prank(WALLET);
        uint256 result = signerModule.checkUserOpSignature(SIGNER_ID, userOp, userOpHash);

        assertEq(result, SIG_VALIDATION_FAILED_UINT, "Should fail when userOpHash signature is missing/invalid");
    }

    function test_WhenProposalHashSignaturesReachThresholdAndUserOpHashSignerIsInvalid() external {
        // it should return SIG_VALIDATION_FAILED_UINT

        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);
        bytes32 proposalHash = _computeProposalHash(userOp);

        // Sort guardian1 and guardian2 for proposalHash signatures
        address lowerAddr;
        address higherAddr;
        uint256 lowerKey;
        uint256 higherKey;

        if (guardian1 < guardian2) {
            lowerAddr = guardian1;
            lowerKey = guardian1Key;
            higherAddr = guardian2;
            higherKey = guardian2Key;
        } else {
            lowerAddr = guardian2;
            lowerKey = guardian2Key;
            higherAddr = guardian1;
            higherKey = guardian1Key;
        }

        // Sign proposalHash with sorted order
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(lowerKey, proposalHash);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(higherKey, proposalHash);

        // Sign userOpHash with non-guardian
        (address invalidSigner, uint256 invalidKey) = makeAddrAndKey("invalidGuardian");
        (uint8 v3, bytes32 r3, bytes32 s3) = vm.sign(invalidKey, userOpHash);

        // Build signature
        bytes memory signature = abi.encodePacked(r1, s1, v1, r2, s2, v2, r3, s3, v3);

        userOp.signature = signature;

        vm.prank(WALLET);
        uint256 result = signerModule.checkUserOpSignature(SIGNER_ID, userOp, userOpHash);

        assertEq(result, SIG_VALIDATION_FAILED_UINT, "Should fail when userOpHash signer is not a guardian");
    }

    modifier whenValidMulti_sigWithDifferentGuardiansForProposalHashAndUserOpHash() {
        _;
    }

    function test_GivenCombinedWeightMeetsThreshold()
        external
        whenValidMulti_sigWithDifferentGuardiansForProposalHashAndUserOpHash
    {
        // it should return SIG_VALIDATION_SUCCESS_UINT

        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);
        bytes32 proposalHash = _computeProposalHash(userOp);

        // Guardian1 (50) signs proposalHash
        // Guardian2 (30) signs userOpHash
        // Total weight = 80 >= threshold (60)

        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(guardian1Key, proposalHash);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(guardian2Key, userOpHash);

        bytes memory signature = abi.encodePacked(r1, s1, v1, r2, s2, v2);

        userOp.signature = signature;

        vm.prank(WALLET);
        uint256 result = signerModule.checkUserOpSignature(SIGNER_ID, userOp, userOpHash);

        assertEq(result, SIG_VALIDATION_SUCCESS_UINT, "Should succeed when combined weight meets threshold");
    }

    function test_GivenCombinedWeightDoesNotMeetThreshold()
        external
        whenValidMulti_sigWithDifferentGuardiansForProposalHashAndUserOpHash
    {
        // it should return SIG_VALIDATION_FAILED_UINT

        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);
        bytes32 proposalHash = _computeProposalHash(userOp);

        // Guardian3 (20) signs proposalHash
        // Guardian2 (30) signs userOpHash (assuming they are different signers)
        // Total weight = 50 < threshold (60)

        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(guardian3Key, proposalHash);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(guardian2Key, userOpHash);

        bytes memory signature = abi.encodePacked(r1, s1, v1, r2, s2, v2);

        userOp.signature = signature;

        vm.prank(WALLET);
        uint256 result = signerModule.checkUserOpSignature(SIGNER_ID, userOp, userOpHash);

        assertEq(result, SIG_VALIDATION_FAILED_UINT, "Should fail when combined weight does not meet threshold");
    }

    function test_WhenGuardianWithLowerAddressSignsUserOpHash() external {
        // it should return SIG_VALIDATION_SUCCESS_UINT because no sorted order required for last signer

        PackedUserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = ENTRYPOINT.getUserOpHash(userOp);
        bytes32 proposalHash = _computeProposalHash(userOp);

        // Determine which guardian has a higher address to sign proposalHash
        // and which has a lower address to sign userOpHash
        // This tests that the last signer (userOpHash) doesn't need to follow sorted order

        address higherAddr;
        uint256 higherKey;
        address lowerAddr;
        uint256 lowerKey;

        if (guardian1 > guardian2) {
            higherAddr = guardian1;
            higherKey = guardian1Key;
            lowerAddr = guardian2;
            lowerKey = guardian2Key;
        } else {
            higherAddr = guardian2;
            higherKey = guardian2Key;
            lowerAddr = guardian1;
            lowerKey = guardian1Key;
        }

        // Higher address guardian signs proposalHash
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(higherKey, proposalHash);

        // Lower address guardian signs userOpHash (this tests that last signer has no sorted requirement)
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(lowerKey, userOpHash);

        // Build signature: higher (proposalHash) + lower (userOpHash)
        // The last signature is for userOpHash and doesn't need to follow sorted order
        bytes memory signature = abi.encodePacked(r1, s1, v1, r2, s2, v2);

        userOp.signature = signature;

        vm.prank(WALLET);
        uint256 result = signerModule.checkUserOpSignature(SIGNER_ID, userOp, userOpHash);

        assertEq(
            result,
            SIG_VALIDATION_SUCCESS_UINT,
            "Should succeed when lower address guardian signs userOpHash (no sorted order required for last signer)"
        );
    }
}
